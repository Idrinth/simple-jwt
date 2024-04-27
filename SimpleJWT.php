<?php

/**!
 * MIT License
 *
 * Copyright (c) 2024 Björn Büttner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace Idrinth\SimpleJWT;

use DateTimeImmutable;
use InvalidArgumentException;

interface SimpleJWT
{
    public const ALGORITHM = 'HS256';
    public const HASH = 'sha256';
    public function getExpiration(): DateTimeImmutable;
    public function getIssuedAt(): DateTimeImmutable;
    public function getData(string $key): int|float|bool|string;
    public function __toString(): string;
}

final class SimpleJWTReader implements SimpleJWT
{
    private DateTimeImmutable $expiresAt;
    private DateTimeImmutable $issuedAt;
    private array $data;

    public function __construct(private string $token, string $secret)
    {
        $parts = explode('.', $token);
        $header = json_decode(base64_decode($parts[0]), false,JSON_THROW_ON_ERROR);
        if ($header->typ !== 'JWT') {
            throw new InvalidArgumentException("Type '{$header->typ}' is not JTW");
        }
        if ($header->alg !== SimpleJWT::ALGORITHM) {
            throw new InvalidArgumentException("Type '{$header->typ}' is not " . SimpleJWT::ALGORITHM);
        }
        if (base64_encode(hash_hmac(SimpleJWT::HASH, "{$parts[0]}.{$parts[1]}", $secret, true)) !== $parts[2]) {
            throw new InvalidArgumentException('Signature failed to validate.');
        }
        $body = json_decode(base64_decode($parts[1]), true,JSON_THROW_ON_ERROR);
        if (!isset($body['exp'])) {
            throw new InvalidArgumentException('JWT has no expiration datetime.');
        }
        if (!isset($body['iat'])) {
            throw new InvalidArgumentException('JWT has no issue datetime.');
        }
        $this->expiresAt = new DateTimeImmutable($body['exp']);
        $this->issuedAt = new DateTimeImmutable($body['iat']);
        if ($this->expiresAt->getTimestamp() > time()) {
            throw new InvalidArgumentException('JWT expired already.');
        }
        $this->data = $body;
    }
    public function getExpiration(): DateTimeImmutable
    {
        return $this->expiresAt;
    }
    public function getIssuedAt(): DateTimeImmutable
    {
        return $this->issuedAt;
    }
    public function getData(string $key): int|float|bool|string
    {
        if (!isset($this->data[$key])) {
            throw new InvalidArgumentException();
        }
        return $this->data[$key];
    }

    public function __toString(): string
    {
        return $this->token;
    }
}

final class SimpleJWTWriter implements SimpleJWT
{
    private DateTimeImmutable $expiresAt;
    private DateTimeImmutable $issuedAt;

    private string $token;

    public function __construct(string $secret, private array $data = [], int $expiresIn = 360)
    {
        $this->expiresAt = new DateTimeImmutable(strtotime("now +{$expiresIn}s"));
        $this->issuedAt = new DateTimeImmutable();
        $data['iat'] = $this->issuedAt->getTimestamp();
        $data['exp'] = $this->expiresAt->getTimestamp();
        $header = json_encode([
            'alg' => SimpleJWT::ALGORITHM,
            'typ' => 'JWT'
        ]);
        $body = json_encode($data);
        $this->token = base64_encode($header) . '.' . base64_encode($body) . '.' . base64_encode(hash_hmac(
            SimpleJWT::HASH,
            "$header.$body",
            $secret,
            true
        ));
    }
    public function __toString(): string
    {
        return $this->token;
    }

    public function getExpiration(): DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function getIssuedAt(): DateTimeImmutable
    {
        return $this->issuedAt;
    }

    public function getData(string $key): int|float|bool|string
    {
        if (!isset($this->data[$key])) {
            throw new InvalidArgumentException();
        }
        return $this->data[$key];
    }
}
