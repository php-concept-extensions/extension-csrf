<?php declare(strict_types=1);

namespace Tests\Unit;

use Concept\Extensions\Csrf\Contracts\CsrfTokenManagerInterface;
use Concept\Extensions\Csrf\Exceptions\CsrfException;
use Concept\Extensions\Csrf\Middleware\HandleCsrfExceptionMiddleware;
use Concept\Extensions\Csrf\Middleware\VerifyCsrfTokenMiddleware;
use Concept\Extensions\Csrf\Protocol\CsrfField;
use Concept\Extensions\Http\Contracts\ResponseFactoryInterface;
use Concept\Extensions\Http\Protocol\HttpHeader;
use Concept\Extensions\Http\Protocol\HttpMethod;
use Concept\Extensions\Http\Protocol\HttpStatusCode;
use Concept\Extensions\Http\Protocol\HttpValue;
use Concept\Extensions\Http\Requests\RequestFormat;
use Concept\Extensions\SessionSymfony\Contracts\FlashBagInterface;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
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

final class HandleCsrfExceptionMiddlewareTest extends TestCase
{
    public function testPassesThroughWhenNoExceptionThrown(): void
    {
        $middleware = new HandleCsrfExceptionMiddleware(
            $this->createMock(ResponseFactoryInterface::class),
            new RequestFormat(),
            $this->createMock(FlashBagInterface::class),
        );
        $response = new Response();
        $handler = new class($response) implements RequestHandlerInterface {
            public function __construct(private ResponseInterface $response) {}

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->response;
            }
        };

        $this->assertSame($response, $middleware->process(new ServerRequest(), $handler));
    }

    public function testReturnsJsonErrorForJsonRequests(): void
    {
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects($this->once())->method('jsonError')->with(
            $this->isType('string'),
            HttpStatusCode::PAGE_EXPIRED,
        )->willReturn(new Response());

        $middleware = new HandleCsrfExceptionMiddleware(
            $responseFactory,
            new RequestFormat(),
            $this->createMock(FlashBagInterface::class),
        );
        $request = (new ServerRequest())->withHeader(HttpHeader::ACCEPT, HttpValue::JSON);
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                throw new CsrfException();
            }
        };

        $middleware->process($request, $handler);
    }

    public function testRedirectsBackForWebRequests(): void
    {
        $flashBag = $this->createMock(FlashBagInterface::class);
        $flashBag->expects($this->once())->method('addError');

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects($this->once())->method('redirectBack')->willReturn(new Response());

        $middleware = new HandleCsrfExceptionMiddleware(
            $responseFactory,
            new RequestFormat(),
            $flashBag,
        );
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                throw new CsrfException();
            }
        };

        $middleware->process(new ServerRequest(), $handler);
    }
}
