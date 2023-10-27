<?php

namespace PrivateLibs\LaravelJwtGuard;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\UserProvider;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use Predis\Client as RedisClient;
use GuzzleHttp\Client as HttpClient;

class LaravelJwtGuard implements Guard
{
    private RedisClient $redis;
    private HttpClient $http;

    public function __construct($request, UserProvider $provider)
    {
        $this->request = $request;
        $this->provider = $provider;

        $this->redis = new RedisClient([
            'host' => env('REDIS_HOST'),
        ]);
        $this->http = new HttpClient();
    }

    public function getProvider()
    {
        return $this->provider;
    }

    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;
    }

    public function check()
    {
        return ! is_null($this->user());
    }

    public function forgetUser()
    {
        $this->user = null;

        return $this;
    }

    public function guest()
    {
        return !$this->check();
    }

    public function id()
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }
    }

    public function validate(array $credentials = [])
    {
    }

    public function hasUser()
    {
        return ! is_null($this->user);
    }

    public function setUser(AuthenticatableContract $user)
    {
        $this->user = $user;

        return $this;
    }

    public function user(): ?Authenticatable
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $payload = $this->verifyToken();
        dd($payload);
        $user = $this->provider->retrieveById($payload);
        if ($payload && !is_null($user)) {
            $this->setUser($user);
            return $user;
        }
        return null;
    }

    public function authenticate()
    {
        if (! is_null($user = $this->user())) {
            return $user;
        }

        throw new \Exception('Unauthenticated');
    }

    private function verifyToken(): ?object
    {
        $token = $this->request->bearerToken();
        if (!$token) return null;

        $kid = $this->getKid($token);
        $publicKey = $this->redis->get($kid);

        if ($kid && $publicKey) {
            return JWT::decode($token, new Key($publicKey, 'RS256'));
        }
        $this->updatePublicKey('beeon');

        $publicKey = $this->redis->get($kid);

        return JWT::decode($token, new Key($publicKey, 'RS256'));

        //return null;
    }

    private function updatePublicKey(string $serverName)
    {
        $response = $this->http->request('GET', env('STS_ENDPOINT') . "{$serverName}/.well-known/jwks");
        $rawBody = (string)$response->getBody();
        $jwks = json_decode($rawBody, true);
        if (!empty($jwks['keys'])) {
            foreach ($jwks['keys'] as $jwk) {
                $this->redis->set($jwk['kid'], $this->jwkToPem($jwk), 'EX', 300);
            }
        }

    }

    private function jwkToPem(array $jwk): ?string
    {
        if (isset($jwk['e']) && isset($jwk['n'])) {
            return RSA::loadPublicKey([
                'e' => new BigInteger(JWT::urlsafeB64Decode($jwk['e']), 256),
                'n' => new BigInteger(JWT::urlsafeB64Decode($jwk['n']), 256),
            ]);
        }
        return null;
    }

    private function getKid(string $jwt): ?string
    {
        $tks = explode('.', $jwt);
        if (count($tks) === 3) {
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode($tks[0]));
            if (isset($header->kid)) {
                return $header->kid;
            }
        }
        return null;
    }
}
