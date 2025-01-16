
<?php

namespace DouglasResende\OAuth2Client;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Class OAuth2Client
 * @package OAuth2Client
 */
class OAuth2Client
{
    /**
     * @var mixed|null
     */
    private $service;

    /**
     * @var
     */
    protected $configs;

    /**
     * @var mixed
     */
    protected $sharedConfigs;

    /**
     * @var string
     */
    protected $cacheKeyPrefix = 'oauth2-client';

    /**
     * @var string
     */
    protected $cacheKey = 'oauth_tokens';

    /**
     * @var
     */
    protected $guzzleResponse;

    /**
     * @var
     */
    protected $response;

    /**
     * @var
     */
    protected $client;

    /**
     * @var array
     */
    protected $oauthTokens = [];

    // Grant Types
    /**
     *
     */
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';

    /**
     *
     */
    const GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code';

    /**
     *
     */
    const GRANT_TYPE_PASSWORD = 'password';

    /**
     *
     */
    const GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';

    /**
     * @var null
     */
    protected $oauthTokenGrantType = null;

    /**
     * @var array
     */
    protected $oauthGrantRequestData = [
        self::GRANT_TYPE_CLIENT_CREDENTIALS => [],
        self::GRANT_TYPE_AUTHORIZATION_CODE => [],
        self::GRANT_TYPE_PASSWORD => [],
        self::GRANT_TYPE_REFRESH_TOKEN => [],
    ];

    /**
     * @var mixed
     */
    protected $environment;

    /**
     * OAuth2Client constructor.
     * @param null $service
     */
    public function __construct($service = null, $configs = [])
    {
        $this->environment = env('APP_ENV');
        $this->sharedConfigs = $this->getConfig('shared_configs');

        if(!empty($configs)) {
            $this->sharedConfigs = array_merge($this->sharedConfigs, $configs);
        }

        $services = $this->getConfig('services');
        $this->service = $service;

        // use default service name
        if (empty($this->service)) {
            $this->service = $this->getConfig('default_service');
        }

        $services = $services[$this->environment];

        // check service configs
        if (!isset($services[$this->service])) {
            throw new RuntimeException("Host [$service] is not found in environment [{$this->environment}] configuration.");
        }

        $this->setServiceConfig($services[$this->service]);

        $base_uri = $this->getServiceConfig('base_uri');
        $base_uri = $this->normalizeUri($base_uri);

        $guzzle_client_config = $this->getConfig('guzzle_client_config', []);
        $this->client = new Client(array_merge($guzzle_client_config, ['base_uri' => $base_uri, 'http_errors' => false]));
    }

    public function getCacheKeyPrefix()
    {
        return $this->cacheKeyPrefix;
    }

    public function setCacheKeyPrefix($cacheKeyPrefix)
    {
        $this->cacheKeyPrefix = $cacheKeyPrefix;

        return $this;
    }

    public function getCacheKey()
    {
        return $this->cacheKey;
    }

    public function setCacheKey($cacheKey)
    {
        $this->cacheKey = $cacheKey;

        return $this;
    }

    /**
     * @param $clientId
     * @param $clientSecret
     * @param $username
     * @param $password
     * @param string $scope
     * @return OAuth2Client
     */
    public function withOAuthTokenTypePassword($clientId, $clientSecret, $username, $password, $scope = '')
    {
        $requestData = [
            'grant_type' => self::GRANT_TYPE_PASSWORD,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'username' => $username,
            'password' => $password,
            'scope' => $scope
        ];

        return $this->withOAuthToken(self::GRANT_TYPE_PASSWORD, $requestData);
    }

    /**
     * @param $clientId
     * @param $clientSecret
     * @param string $scope
     * @return OAuth2Client
     */
    public function withOAuthTokenTypeClientCredentials($clientId, $clientSecret, $scope = '')
    {
        $requestData = [
            'grant_type' => self::GRANT_TYPE_CLIENT_CREDENTIALS,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'scope' => $scope
        ];

        return $this->withOAuthToken(self::GRANT_TYPE_CLIENT_CREDENTIALS, $requestData);
    }

    /**
     * @param $clientId
     * @param $clientSecret
     * @param $redirectUri
     * @param $code
     * @return OAuth2Client
     */
    public function withOAuthTokenTypeAuthorizationCode($clientId, $clientSecret, $redirectUri, $code)
    {
        $requestData = [
            'grant_type' => self::GRANT_TYPE_AUTHORIZATION_CODE,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'redirect_uri' => $redirectUri,
            'code' => $code,
        ];

        return $this->withOAuthToken(self::GRANT_TYPE_AUTHORIZATION_CODE, $requestData);
    }

    private function withOAuthTokenTypeRefreshToken($clientId, $refreshToken, $clientSecret, $code)
    {
        $requestData = [
            'grant_type' => self::GRANT_TYPE_REFRESH_TOKEN,
            'refresh_token' => $refreshToken,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'code' => $code,
        ];

        return $this->withOAuthToken(self::GRANT_TYPE_REFRESH_TOKEN, $requestData);
    }

    /**
     * @return $this
     */
    public function withoutOAuthToken()
    {
        $this->oauthTokenGrantType = null;
        return $this;
    }

    /**
     * @param string $uri
     * @param array $query
     * @param array $options
     * @param bool $api
     * @return $this ;
     */
    public function get($uri, array $query = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->get($uri, array_merge($options, ['query' => $query,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $options
     * @param bool $api
     * @return $this;
     */
    public function post($uri, array $data = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->post($uri, array_merge($options, ['form_params' => $data,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @url http://docs.guzzlephp.org/en/latest/quickstart.html#sending-form-files
     * @param $uri
     * @param array $multipart
     * @param array $options
     * @param bool $api
     * @return $this;
     */
    public function postMultipart($uri, array $multipart = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->post($uri, array_merge($options, ['multipart' => $multipart,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @param $uri
     * @param array $data
     * @param array $options
     * @param bool $api
     * @return $this;
     */
    public function postMultipartSimple($uri, array $data = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $multipart = [];
        foreach ($data as $key => $value) {
            $multipart[] = [
                'name' => $key,
                'contents' => $value,
            ];
        }
        $response = $this->client->post($uri, array_merge($options, ['multipart' => $multipart,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    public function postJson($uri, array $data = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->post($uri, array_merge($options, [RequestOptions::JSON => $data,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $options
     * @param bool $api
     * @return $this;
     */
    public function head($uri, array $data = [], array $options = [], $api = true)
    {
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->head($uri, array_merge($options, ['body' => $data,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $options
     * @param bool $api
     * @return $this;
     */
    public function put($uri, array $data = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->put($uri, array_merge($options, ['form_params' => $data,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $options
     * @param bool $api
     * @return $this;
     */
    public function patch($uri, array $data = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->patch($uri, array_merge($options, ['form_params' => $data,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @param string $uri
     * @param array $data
     * @param array $options
     * @param bool $api
     * @return $this;
     */
    public function delete($uri, array $data = [], array $options = [], $api = true)
    {
        $options = $this->configureOptions($options);
        $uri = $api ? $this->getServiceConfig('api_url') . $uri : $uri;
        $response = $this->client->delete($uri, array_merge($options, ['form_params' => $data,]));
        $this->setGuzzleResponse($response);
        return $this;
    }

    /**
     * @param $key
     * @param null $default
     * @return mixed
     */
    private function getConfig($key, $default = null)
    {
        return config("oauth2-client.$key", $default);
    }

    /**
     * @param $key
     * @return mixed
     */
    private function getServiceConfig($key)
    {
        if(isset($this->configs[$key])) {
            return $this->configs[$key];
        }
        return null;
    }

    /**
     * @param array $config
     */
    private function setServiceConfig(array $config = [])
    {
        $sharedConfigs = $this->sharedConfigs;

        $this->configs = $this->mergeConfig($sharedConfigs, $config);
    }

    /**
     * @param array $baseConfig
     * @param array $newConfig
     * @return array
     */
    private function mergeConfig($baseConfig = [], $newConfig = [])
    {
        $combined_service_config = $newConfig;

        foreach ($baseConfig as $key => $config) {
            if (is_array($config) && isset($combined_service_config[$key])) {
                $combined_service_config[$key] = array_merge($config, $combined_service_config[$key]);
            } else if (!isset($combined_service_config[$key])) {
                $combined_service_config[$key] = $config;
            }
        }
        return $combined_service_config;
    }

    /**
     * @param $grant_type
     * @param array|null $requestData
     * @return $this
     */
    private function withOAuthToken(string $grant_type, array $requestData)
    {
        if (!empty($requestData)) {
            $this->setOAuthGrantRequestData($grant_type, $requestData);
        }
        $this->getOAuthToken($grant_type, $requestData);
        $this->oauthTokenGrantType = $grant_type;
        return $this;
    }

    /**
     * @param string $grant_type
     * @param array $requestData
     * @return mixed
     */
    private function getOAuthToken(string $grant_type, array $requestData = [])
    {
        $this->oauthTokens = Cache::get($this->getOauthTokensCacheKey(), []);

        if (!isset($this->oauthTokens[$grant_type])) {
            // request access token
            $this->postRequestAccessToken($grant_type, $this->getOAuthGrantRequestData($grant_type, $requestData));

            // handle access token
            if ($this->getResponse()->getStatusCode() != 200) {
                throw new RuntimeException('Failed to get access token for grant type [' . $grant_type . ']!');
            }

            $data = $this->getResponseAsArray();

            if (!isset($data['access_token'])) {
                throw new RuntimeException('"access_token" is not set in response!');
            }
            $access_token = $data['access_token'];
            $this->setOAuthToken($grant_type, $access_token, ((int)$data['expires_in'] / 60));
        }

        return $this->oauthTokens[$grant_type];
    }

    protected function normalizeUri(?string $uri) {
        if (!$uri) {
            return $uri;
        }

        if (!Str::endsWith($uri, '/')) {
            $uri .= '/';
        }

        return $uri;
    }

    /**
     * @param $type
     * @param $access_token
     * @param $minutes
     */
    private function setOAuthToken($type, $access_token, $minutes)
    {
        if (empty($access_token)) {
            unset($this->oauthTokens[$type]);
        } else {
            $this->oauthTokens[$type] = $access_token;
        }

        Cache::put($this->getOauthTokensCacheKey(), $this->oauthTokens, $minutes);
    }

    /**
     * @param $grant_type
     * @param array $data
     */
    public function setOAuthGrantRequestData($grant_type, array $data)
    {
        $this->oauthGrantRequestData[$grant_type] = $data;
    }

    /**
     * @param $options
     * @return array
     */
    private function configureOptions($options)
    {
        $headers = $this->getServiceConfig('headers');

        $cert = $this->getServiceConfig('cert');
        if(!empty($cert)){
            $options['cert'] = $cert;
        }

        $sslKey = $this->getServiceConfig('ssl_key');
        if(!empty($sslKey)){
            $options['ssl_key'] = $sslKey;
        }

        $verify = $this->getServiceConfig('verify');
        $options['verify'] = $verify;

        // add client ip to header
        $request = request();
        $clientIp = $request->getClientIp();
        $headers['X-OAuth2Client-Ip'] = $clientIp;
        $headers['X-Forwarded-For'] = $clientIp;
        $headers['Accept-Language'] = $request->header('Accept-Language', app()->getLocale());

        if ($this->oauthTokenGrantType) {
            $headers['Authorization'] = 'Bearer ' . $this->getOAuthToken($this->oauthTokenGrantType);
        }

        if (isset($options['headers'])) {
            $headers = array_merge($headers, $options['headers']);
            unset($options['headers']);
        }

        return array_merge(['headers' => $headers,], $options);
    }

    /**
     * @return string
     */
    private function getOauthTokensCacheKey()
    {
        $cacheKey = [];
        $cacheKey[] = $this->cacheKeyPrefix;
        $cacheKey[] = $this->cacheKey;
        $cacheKey[] = $this->service;
        $cacheKey[] = $this->environment;

        return implode('.', $cacheKey);
    }

    /**
     * @param $grant_type
     * @param $request_data
     * @return array
     */
    protected function getOAuthGrantRequestData($grant_type, $request_data)
    {
        if (!isset($this->oauthGrantRequestData[$grant_type])) {
            throw new RuntimeException('[' . $grant_type . '] was not found in "oauthGrantRequestData"');
        }

        $data = $this->oauthGrantRequestData[$grant_type];
        return array_merge($request_data, $data);
    }


    /**
     * @param $grant_type
     * @param $data
     * @return OAuth2Client
     */
    protected function postRequestAccessToken($grant_type, $data)
    {
        $authUri = $this->getAuthUri();
        $url = $this->getServiceConfig('oauth2_access_token_url');

        if ($authUri) {
            $url = $authUri . $url;
        }

        return $this->post($url, array_merge($data, ['grant_type' => $grant_type,]), [], false);
    }

    protected function getAuthUri() {
        $authUri = $this->getServiceConfig('auth_uri');
        return $this->normalizeUri($authUri);
    }

    /**
     * @param bool $assoc
     * @return mixed
     */
    public function getResponseAsArray($assoc = true)
    {
        return json_decode($this->getResponse()->getContent(), $assoc);
    }

    /**
     * @return Response
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * @param Response $response
     */
    protected function setResponse(Response $response)
    {
        $this->response = $response;
        $statusCode = $this->response->getStatusCode();

        switch ($statusCode) {
            case 401:
                Cache::forget($this->getOauthTokensCacheKey());
        }
    }

    /**
     * @param ResponseInterface $response
     */
    protected function setGuzzleResponse(ResponseInterface $response)
    {
        $this->guzzleResponse = $response;
        $this->setResponse(new Response($response->getBody(), $response->getStatusCode(), $response->getHeaders()));
    }
}
