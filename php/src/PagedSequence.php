<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/**
 * A lazy listing: pages are fetched as the sequence is iterated, following `rel="next"` links (a page seen before
 * ends the listing). Each `foreach` starts again from the first page.
 *
 * ```php
 * foreach ($client->listContainer($folder) as $item) {
 *     echo $item->id, "\n";
 * }
 * ```
 *
 * @template T
 * @implements \IteratorAggregate<int, T>
 */
final class PagedSequence implements \IteratorAggregate
{
    /**
     * @param \Closure(): array{0: list<T>, 1: ?string} $load the first page: its elements and the next page's URL
     * @param \Closure(string): array{0: list<T>, 1: ?string} $fetch a further page
     * @internal
     */
    public function __construct(private readonly string $first, private readonly \Closure $load, private readonly \Closure $fetch)
    {
    }

    /** @return \Generator<int, T> */
    public function getIterator(): \Generator
    {
        $seen = [$this->first => true];
        [$elements, $next] = ($this->load)();
        $i = 0;
        while (true) {
            foreach ($elements as $e) {
                yield $i++ => $e;
            }
            if ($next === null || isset($seen[$next])) {
                return;
            }
            $seen[$next] = true;
            [$elements, $next] = ($this->fetch)($next);
        }
    }

    /**
     * Every element, fetching every page.
     *
     * @return list<T>
     */
    public function toArray(): array
    {
        return iterator_to_array($this->getIterator(), false);
    }

    /**
     * The first `n` elements, fetching only the pages needed.
     *
     * @return list<T>
     */
    public function take(int $n): array
    {
        $out = [];
        if ($n <= 0) {
            return $out;
        }
        foreach ($this as $e) {
            $out[] = $e;
            if (count($out) >= $n) {
                break;
            }
        }
        return $out;
    }
}
