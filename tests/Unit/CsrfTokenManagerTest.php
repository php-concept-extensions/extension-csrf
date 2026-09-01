<?php declare(strict_types=1);

namespace Tests\Unit;

use Concept\Extensions\Csrf\CsrfTokenManager;
use Concept\Extensions\Csrf\Protocol\CsrfField;
use Concept\Extensions\SessionSymfony\Contracts\SessionInterface;
use PHPUnit\Framework\TestCase;

final class CsrfTokenManagerTest extends TestCase
{
    /** @var array<string, mixed> */
    private array $sessionStorage = [];

    private SessionInterface $session;

    private CsrfTokenManager $manager;

    protected function setUp(): void
    {
        $this->sessionStorage = [];
        $this->session = $this->createMock(SessionInterface::class);
        $this->session->method('has')->willReturnCallback(
            fn(string $key): bool => array_key_exists($key, $this->sessionStorage),
        );
        $this->session->method('get')->willReturnCallback(
            fn(string $key, mixed $default = null): mixed => $this->sessionStorage[$key] ?? $default,
        );
        $this->session->method('set')->willReturnCallback(
            function(string $key, mixed $value): void {
                $this->sessionStorage[$key] = $value;
            },
        );

        $this->manager = new CsrfTokenManager($this->session);
    }

    public function testGetTokenGeneratesAndPersistsHexToken(): void
    {
        $token = $this->manager->getToken();

        $this->assertSame(64, strlen($token));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $token);
        $this->assertSame($token, $this->manager->getToken());
    }

    public function testGetTokenReturnsEmptyStringWhenSessionValueIsNotString(): void
    {
        $this->sessionStorage[CsrfField::NAME] = 12345;

        $this->assertSame('', $this->manager->getToken());
    }

    public function testValidateReturnsTrueForMatchingToken(): void
    {
        $token = $this->manager->getToken();

        $this->assertTrue($this->manager->validate($token));
    }

    public function testValidateReturnsFalseForMissingOrEmptyToken(): void
    {
        $this->manager->getToken();

        $this->assertFalse($this->manager->validate(null));
        $this->assertFalse($this->manager->validate(''));
    }

    public function testValidateReturnsFalseForMismatchedToken(): void
    {
        $this->manager->getToken();

        $this->assertFalse($this->manager->validate(str_repeat('a', 64)));
    }

    public function testValidateReturnsFalseWhenSessionHasNoToken(): void
    {
        $this->assertFalse($this->manager->validate('token'));
    }

    public function testValidateReturnsFalseWhenSessionTokenIsNotString(): void
    {
        $this->sessionStorage[CsrfField::NAME] = ['token' => 'value'];

        $this->assertFalse($this->manager->validate('token'));
    }
}
