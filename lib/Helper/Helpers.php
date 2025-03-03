<?php

declare(strict_types=1);

namespace OCA\EduSoft\Helper;

use Exception;
require_once __DIR__ . '/../../vendor-bin/php-jwt/src/Key.php';
require_once __DIR__ . '/../../vendor-bin/php-jwt/src/JWT.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Helpers
{
    public  $JWT_SECRET = "2ZmRAqyN47GyE1Fm6ElhorU4Ai4eg934maERKd8bUKqBVkdBfVKD8KqpcToexGf5";
    public function __construct() {}
    public  function decodeJwt($jwt)
    {
        
        try {
            $decode_token = JWT::decode($jwt, new Key($this->JWT_SECRET, 'HS256'));
            $decode_arr = (array) $decode_token;

            return $decode_arr;
        } catch (\Throwable $th) {
            //throw $th;
            throw new Exception($th->getMessage());
        }
    }
}
