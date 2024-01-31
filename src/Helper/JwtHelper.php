<?php

namespace Mia\Auth\Helper;

use \Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Description of MiaAuthMiddleware
 *
 * @author matiascamiletti
 */
trait JwtHelper
{
    /**
     * string
     * 
     * api-key
     * jwt
     */
    protected $method = 'api-key';
    /**
     * API KEY
     */
    protected $key = '';
    /**
     * 
     */
    protected $iss = '';
    /**
     * 
     */
    protected $aud = '';
    /**
     * 
     */
    protected $expire = 'P15D';
    /**
     * If valid status of user
     * Si valida el estado de la cuenta del  usuario
     */
    protected $validStatus = false;
    /**
     * 
     */
    protected function useJwtWithResponse(\Mia\Auth\Model\MIAUser $account): \Psr\Http\Message\ResponseInterface
    {
        $accessToken = '';
        try {
            $accessToken = $this->generateToken($account->id, $account->email);
        } catch (\Exception $th) {
            return new \Mia\Core\Diactoros\MiaJsonErrorResponse(-3, 'Problem with generate token');
        }

        $data = $account->toArray();
        $data['token_type'] = 'bearer';
        $data['access_token'] = $accessToken;

        return new \Mia\Core\Diactoros\MiaJsonResponse($data);
    }
    /**
     * 
     */
    public function generateToken($userId, $email)
    {
        return JWT::encode(array(
            'iss' => $this->iss,
            'aud' => $this->aud,
            'iat' => (new \DateTime())->getTimestamp(),
            'nbf' => (new \DateTime())->getTimestamp(),
            'exp' => (new \DateTime())->add(new \DateInterval($this->expire))->getTimestamp(),
            'uid' => $userId,
            'data' => array(
                'id' => $userId,
                'email' => $email
            )
        ), $this->key, 'HS256');
    }
    /**
     * 
     */
    public function decodeToken($token)
    {
        return JWT::decode($token, new Key($this->key, 'HS256'));
    }

    /**
     * Funcion que se encarga de obtener los parametros necesarios
     * @param array $config
     */
    public function setConfig($config)
    {
        if(array_key_exists('method', $config)){
            $this->method = $config['method'];
        }
        if(array_key_exists('key', $config)){
            $this->key = $config['key'];
        }
        if(array_key_exists('iss', $config)){
            $this->iss = $config['iss'];
        }
        if(array_key_exists('aud', $config)){
            $this->aud = $config['aud'];
        }
        if(array_key_exists('expire', $config)){
            $this->expire = $config['expire'];
        }
        if(array_key_exists('valid_status', $config) && $config['valid_status'] === true){
            $this->validStatus = $config['valid_status'];
        }
    }
}
