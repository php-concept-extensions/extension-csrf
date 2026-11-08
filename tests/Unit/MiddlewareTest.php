<?php declare(strict_types=1);

namespace Tests\Unit;

use Concept\Extensions\Csrf\Contracts\CsrfTokenManagerInterface;
use Concept\Extensions\Csrf\Exceptions\CsrfException;
use Concept\Extensions\Csrf\Middleware\VerifyCsrfTokenMiddleware;
use Concept\Extensions\Csrf\Protocol\CsrfField;
use Concept\Extensions\Http\Protocol\HttpHeader;
use Concept\Extensions\Http\Protocol\HttpMethod;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Tests\Support\RecordingRequestHandler;

final class VerifyCsrfTokenMiddlewareTest extends TestCase
{
    public function testGetRequestPassesThroughWithoutValidation(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects($this->never())->method('validate');

        $middleware = new VerifyCsrfTokenMiddleware($manager);
        $handler = new RecordingRequestHandler();

        $middleware->process(new ServerRequest(), $handler);

        $this->assertNotNull($handler->request);
    }

    public function testPostWithValidTokenCallsHandler(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->method('validate')->with('token-123')->willReturn(true);

        $middleware = new VerifyCsrfTokenMiddleware($manager);
        $handler = new RecordingRequestHandler();
        $request = (new ServerRequest())
            ->withMethod(HttpMethod::POST)
            ->withParsedBody([CsrfField::NAME => 'token-123']);

        $middleware->process($request, $handler);

        $this->assertSame($request, $handler->request);
    }

    public function testPostWithInvalidTokenThrowsCsrfException(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->method('validate')->willReturn(false);

        $middleware = new VerifyCsrfTokenMiddleware($manager);
        $request = (new ServerRequest())->withMethod(HttpMethod::POST);

        $this->expectException(CsrfException::class);
        $middleware->process($request, new RecordingRequestHandler());
    }

    public function testReadsTokenFromHeader(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects($this->once())->method('validate')->with('header-token')->willReturn(true);

        $middleware = new VerifyCsrfTokenMiddleware($manager);
        $request = (new ServerRequest())
            ->withMethod(HttpMethod::DELETE)
            ->withHeader(HttpHeader::X_CSRF_TOKEN, 'header-token');

        $middleware->process($request, new RecordingRequestHandler());
    }
}
