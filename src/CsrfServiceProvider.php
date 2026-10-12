<?php declare(strict_types=1);

namespace Concept\Extensions\Csrf;

use Closure;
use Concept\Extensions\Csrf\Contracts\CsrfTokenManagerInterface;
use Concept\Extensions\Event\Events\ExtensionAwakened;
use Concept\Extensions\Event\Support\EventDispatcherResolver;
use Concept\Extensions\SessionSymfony\Contracts\SessionInterface;
use Concept\Support\FactoryResolver;
use League\Container\ServiceProvider\AbstractServiceProvider;

final class CsrfServiceProvider extends AbstractServiceProvider
{
    private const string EXTENSION_NAME = 'csrf';

    /**
     * @param Closure(): mixed $sessionFactory
     */
    public function __construct(
        private readonly Closure $sessionFactory,
    ) {}

    public function provides(string $id): bool
    {
        return in_array($id, [
            CsrfTokenManagerInterface::class,
        ], true);
    }

    public function register(): void
    {
        $container = $this->getContainer();

        $container->add(CsrfTokenManagerInterface::class, function() use ($container): CsrfTokenManager {
            EventDispatcherResolver::optional($container)?->dispatch(new ExtensionAwakened(
                extensionName: self::EXTENSION_NAME,
                anchorId: CsrfTokenManagerInterface::class,
            ));

            $sessionFactory = $this->sessionFactory;
            $session = FactoryResolver::required($sessionFactory, SessionInterface::class, 'Session factory result');

            return new CsrfTokenManager($session);
        })->setShared(true);
    }
}
