<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use Http\Discovery\MessageFactoryDiscovery;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class WeChatResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritdoc}
     */
    protected $paths = [
        'identifier' => 'openid',
        'nickname' => 'nickname',
        'realname' => 'nickname',
        'profilepicture' => 'headimgurl',
    ];

    /**
     * {@inheritdoc}
     */
    public function getResponseContent(ResponseInterface $rawResponse)
    {
        $content = (string)$rawResponse->getBody();
        if (preg_match('/^callback\((.+)\);$/', $content, $matches)) {
            $rawResponse = MessageFactoryDiscovery::find()
                ->createResponse(
                    $rawResponse->getStatusCode(),
                    null,
                    $rawResponse->getHeaders(),
                    trim($matches[1])
                );
        }

        return parent::getResponseContent($rawResponse);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInformation(array $accessToken = null, array $extraParameters = [], $language = 'zh_CN')
    {
        $openid = $extraParameters['openid'] ?? $this->requestUserIdentifier($accessToken);

        $url = $this->normalizeUrl($this->options['infos_url'], [
            'oauth_consumer_key' => $this->options['client_id'],
            'access_token' => $accessToken['access_token'],
            'openid' => $openid,
            'lang' => $language,
            'format' => 'json',
        ]);

        $response = $this->doGetUserInformationRequest($url);
        $content = $this->getResponseContent($response);

        // Custom errors:
        if (isset($content['ret']) && 0 === $content['ret']) {
            $content['openid'] = $openid;
        } else {
            throw new AuthenticationException(sprintf('OAuth error: %s', isset($content['ret']) ? $content['msg'] : 'invalid response'));
        }

        $response = $this->getUserResponse();
        $response->setData($content);
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }

    public function applet($appId, $code, $secret, $encryptedData, $iv)
    {
        $url = $this->normalizeUrl($this->options['applet_session_key_url'], [
            'appid' => $appId,
            'secret' => $secret,
            'js_code' => $code,
            'grant_type' => 'authorization_code',
        ]);

        $response = $this->httpRequest($url);
        $content = $this->getResponseContent($response);

        if (!isset($content['openid']) || !isset($content['session_key'])) {
            switch ($content['errcode']) {
                case -1:
                    throw new AuthenticationException('WeChat Applet error: The system is busy. Please try again later');
                    break;
                case -40029:
                    throw new AuthenticationException('WeChat Applet error: Code is invalid');
                    break;
                case -45011:
                    throw new AuthenticationException('WeChat Applet error: Frequency limit, 100 beats per minute per user');
                    break;
                default:
                    throw new AuthenticationException('WeChat Applet error: invalid response');
            }

        }

        $appletUser = $this->decryptionApplet($appId, $content['session_key'], $encryptedData, $iv, $data);

        return $appletUser;
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'authorization_url' => 'https://open.weixin.qq.com/connect/qrconnect?format=json',
            'access_token_url' => 'https://api.weixin.qq.com/sns/oauth2/access_token',
            'infos_url' => 'https://api.weixin.qq.com/sns/userinfo',
            'applet_session_key_url' => 'https://api.weixin.qq.com/sns/jscode2session',
        ]);
    }

    /**
     * @param $appId
     * @param $sessionKey
     * @param $encryptedData
     * @param $iv
     * @param $data
     * @return mixed
     */
    private function decryptionApplet($appId, $sessionKey, $encryptedData, $iv, &$data)
    {
        if (strlen($sessionKey) != 24) {
            throw new AuthenticationException(sprintf('WeChat Applet error: sessionKey length must be 16, 24, or 32 bytes; got sessionKey len (%s).', strlen($sessionKey)));
        }
        $aesKey = base64_decode($sessionKey);

        if (strlen($iv) != 24) {
            throw new AuthenticationException('WeChat Applet error: iv is invalid');
        }
        $aesIV = base64_decode($iv);

        $aesCipher = base64_decode($encryptedData);

        $result = openssl_decrypt($aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);

        $dataObj = json_decode($result);
        if ($dataObj == NULL) {
            throw new AuthenticationException('WeChat Applet error: The given payload is invalid.');
        }
        if ($dataObj->watermark->appid != $appId) {
            throw new AuthenticationException('WeChat Applet error: The given payload is invalid.');
        }

        $data = $result;

        return json_decode($data, true);;
    }
}
