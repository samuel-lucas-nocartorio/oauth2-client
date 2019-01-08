<?php

return [
    //===================================================================
    // DEBUG MODE
    //===================================================================
    'debug_mode' => true,
    //===================================================================
    // GUZZLE OACLIENT CONFIG
    //===================================================================
    'guzzle_client_config' => [
        'timeout' => 60
    ],

    //===================================================================
    // SHARED CONFIG FOR SERVICES
    //===================================================================
    'shared_configs' => [

        'headers' => [
            'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
        ],

        'api_url' => 'api/',

        'oauth2_access_token_url' => 'oauth/token',

        'oauth2_refresh_token_url' => 'oauth/refresh',

    ],

    //===================================================================
    // DEFAULT SERVICE
    //===================================================================
    'default_service' => 'default',

    //===================================================================
    // SERVICES
    //===================================================================
    'services' => [

        // ENVIRONMENT: LOCAL (DEVELOPMENT)
        'local' => [

            'default' => [

                'base_uri' => 'http://rest-api.com/',

                'headers' => [
                    'Accept' => 'application/json',
                ],
            ],

            'service-1' => [

                'base_uri' => 'http://rest-api-1.local/',

                'headers' => [
                    'Accept' => 'application/json',
                ],
            ],

        ],

        // ENVIRONMENT: PRODUCTION
        'production' => [

            'default' => [

                'base_uri' => 'http://rest-api.com/',

                'headers' => [
                    'Accept' => 'application/json',
                ],
            ],

            'service-1' => [

                'base_uri' => 'http://rest-api-1.com/',

                'headers' => [
                    'Accept' => 'application/json',
                ],
            ],

        ],

    ],
];
