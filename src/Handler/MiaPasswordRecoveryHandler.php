<?php

namespace Mia\Auth\Handler;

use Laminas\Diactoros\Response\JsonResponse;

/**
 * Description of MiaPasswordRecoveryHandler
 *
 * @author matiascamiletti
 */
class MiaPasswordRecoveryHandler extends \Mia\Core\Request\MiaRequestHandler
{
    public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
    {
        // Obtener parametros obligatorios
        $email = $this->getParam($request, 'email', '');
        $password = $this->getParam($request, 'password', '');
        $token = $this->getParam($request, 'token', '');
        // Verificar si ya existe la cuenta
        $account = \Mia\Auth\Model\MIAUser::where('email', $email)->first();
        if($account === null){
            return new JsonResponse(['error' => 'This email does not exist'], 400);
        }
        // Buscar si existe el token
        $recovery = \Mia\Auth\Model\MIARecovery::where('user_id', $account->id)->where('token', $token)->where('status', \Mia\Auth\Model\MIARecovery::STATUS_PENDING)->first();
        if($recovery === null){
            return new JsonResponse(['error' => 'The token is incorrect'], 400);
        }
        $recovery->status = \Mia\Auth\Model\MIARecovery::STATUS_USED;
        $recovery->save();
        // Guardar nueva contraseña
        $account->password = \Mia\Auth\Model\MIAUser::encryptPassword($password);
        $account->save();
        // Devolvemos datos del usuario
        return new \Mia\Core\Diactoros\MiaJsonResponse(true);
    }
}

