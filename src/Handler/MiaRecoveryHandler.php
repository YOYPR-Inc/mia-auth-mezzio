<?php

namespace Mia\Auth\Handler;

use Laminas\Diactoros\Response\JsonResponse;
use Mia\Auth\Helper\JwtHelper;
use Mia\Auth\Model\MIAUser;

/**
 * Description of MiaRecoveryHanlder
 * 
 * @OA\Post(
 *     path="/mia-auth/recovery",
 *     summary="Recovery Password",
 *     tags={"Authentication"},
 *     @OA\RequestBody(
 *         description="Info of User",
 *         required=true,
 *         @OA\MediaType(
 *             mediaType="application/json",                 
 *             @OA\Schema(
 *                  @OA\Property(
 *                      property="email",
 *                      type="string",
 *                      description="Email of user",
 *                      example="matias@agencycoda.com"
 *                  )
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *          response=200,
 *          description="successful operation",
 *          @OA\JsonContent(ref="#/components/schemas/MIAUser")
 *     )
 * )
 *
 * @author matiascamiletti
 */
class MiaRecoveryHandler extends \Mia\Core\Request\MiaRequestHandler
{
    use JwtHelper;

    public function __construct($config)
    {
        // Setear configuración inicial
        $this->setConfig($config);
    }

    public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
    {
        // Obtener parametros obligatorios
        $email = $this->getParam($request, 'email', '');
        // Verificar si ya existe la cuenta
        $account = \Mia\Auth\Model\MIAUser::where('email', $email)->first();

        if ($account === null) {
            return new JsonResponse(['error' => 'Este email no existe'], 404);
        }

        if ($account->deleted == 1) {
            return new JsonResponse(['error' => 'Esta cuenta no existe.'], 404);
        }

        if ($this->validStatus && $account->status == MIAUser::STATUS_PENDING) {
            return new JsonResponse(['error' => 'Tu cuenta no está activa'], 400);

        } elseif ($this->validStatus && $account->status == MIAUser::STATUS_BLOCKED) {
            return new JsonResponse(['error' => 'Tu cuenta está bloqueada'], 400);
        }
        
        // Generar registro de token
        $token = \Mia\Auth\Model\MIAUser::encryptPassword($email . '_' . time() . '_' . $email);
        $recovery = new \Mia\Auth\Model\MIARecovery();
        $recovery->user_id = $account->id;
        $recovery->status = \Mia\Auth\Model\MIARecovery::STATUS_PENDING;
        $recovery->token = $token;
        $recovery->save();
        
        $lang = $this->getParam($request, 'lang', 'en');
        $sendgrid = $request->getAttribute('Sendgrid');
        $result = $sendgrid->send($account->email, 'recovery-password-' . $lang, [
            'firstname' => $account->firstname,
            'email' => $account->email,
            'email_encoded' => urlencode($account->email),
            'token' => $token
        ]);

        return new JsonResponse(['success' => true]);
    }
}
