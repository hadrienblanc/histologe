<?php

namespace App\Tests\HtmlSanitizer;

use Symfony\Component\HtmlSanitizer\Parser\NativeParser;
use Symfony\Component\HtmlSanitizer\Parser\ParserInterface;

/**
 * Parser de repli pour l'environnement de test : utilise l'API Dom\HTMLDocument
 * (PHP >= 8.4 compilé avec libxml2 >= 2.16) quand elle est disponible, et
 * retombe sur l'API DOMDocument historique sinon, afin que la suite de tests
 * puisse tourner sur des PHP 8.4 construits sans support HTML5 de ext-dom.
 *
 * Ce service n'est câblé qu'en environnement de test (voir config/services_test.yaml).
 */
class TestHtmlSanitizerParser implements ParserInterface
{
    private ?NativeParser $nativeParser = null;

    public function parse(string $html, string $context = 'body'): \Dom\Node|\DOMNode|null
    {
        if (class_exists(\Dom\HTMLDocument::class)) {
            return ($this->nativeParser ??= new NativeParser())->parse($html, $context);
        }

        // Repli : parser HTML historique (DOMDocument), API supportée par DomVisitor
        $document = new \DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $loaded = $document->loadHTML(
            \sprintf('<!DOCTYPE html><%s>%s</%1$s>', $context, $html),
            \LIBXML_NOWARNING | \LIBXML_NOERROR
        );
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if (!$loaded) {
            return null;
        }

        $element = $document->getElementsByTagName($context)->item(0);

        return $element?->hasChildNodes() ? $element : null;
    }
}
