<?php

require_once __DIR__.'/_executor.php';

// Self-contained repro of php/frankenphp#2368: a minimal port of Symfony's
// AbstractSessionHandler + StrictSessionHandler. The bug needs (1) a user
// handler that implements SessionUpdateTimestampHandlerInterface so PHP's
// strict-mode path calls validateId -> read() inside ps_call_handler, (2)
// session.use_strict_mode=1, and (3) an existing session file (so
// validateId accepts the shared id). Without those, the lock cycles
// cleanly even when max_execution_time fires.
if (!class_exists('StrictSessionHandler', false)) {
    abstract class AbstractSessionHandler implements SessionHandlerInterface, SessionUpdateTimestampHandlerInterface
    {
        private string $sessionName;
        private string $prefetchId;
        private string $prefetchData;
        private ?string $newSessionId = null;

        public function open(string $savePath, string $sessionName): bool
        {
            $this->sessionName = $sessionName;
            return true;
        }

        abstract protected function doRead(string $sessionId): string;
        abstract protected function doWrite(string $sessionId, string $data): bool;
        abstract protected function doDestroy(string $sessionId): bool;

        public function validateId(string $sessionId): bool
        {
            $this->prefetchData = $this->read($sessionId);
            $this->prefetchId = $sessionId;
            return '' !== $this->prefetchData;
        }

        public function read(string $sessionId): string
        {
            if (isset($this->prefetchId)) {
                $prefetchId = $this->prefetchId;
                $prefetchData = $this->prefetchData;
                unset($this->prefetchId, $this->prefetchData);
                if ($prefetchId === $sessionId || '' === $prefetchData) {
                    $this->newSessionId = '' === $prefetchData ? $sessionId : null;
                    return $prefetchData;
                }
            }
            $data = $this->doRead($sessionId);
            $this->newSessionId = '' === $data ? $sessionId : null;
            return $data;
        }

        public function write(string $sessionId, string $data): bool
        {
            $this->newSessionId = null;
            return $this->doWrite($sessionId, $data);
        }

        public function destroy(string $sessionId): bool
        {
            return $this->newSessionId === $sessionId || $this->doDestroy($sessionId);
        }
    }

    class StrictSessionHandler extends AbstractSessionHandler
    {
        public function __construct(private SessionHandlerInterface $handler) {}

        public function open(string $savePath, string $sessionName): bool
        {
            parent::open($savePath, $sessionName);
            return $this->handler->open($savePath, $sessionName);
        }

        public function updateTimestamp(string $sessionId, string $data): bool
        {
            return $this->write($sessionId, $data);
        }

        protected function doRead(string $sessionId): string
        {
            return $this->handler->read($sessionId);
        }

        protected function doWrite(string $sessionId, string $data): bool
        {
            return $this->handler->write($sessionId, $data);
        }

        protected function doDestroy(string $sessionId): bool
        {
            return $this->handler->destroy($sessionId);
        }

        public function close(): bool
        {
            return $this->handler->close();
        }

        public function gc(int $maxlifetime): int|false
        {
            return $this->handler->gc($maxlifetime);
        }
    }
}

return function () {
    ini_set('session.use_strict_mode', '1');
    session_set_save_handler(new StrictSessionHandler(new SessionHandler()), true);
    session_id('testsession2368xxxxxxxx');
    session_start();

    set_time_limit(10);
    echo "Done.\n";
    flush();
    system('sleep 4');
    echo "ok!\n";
};
