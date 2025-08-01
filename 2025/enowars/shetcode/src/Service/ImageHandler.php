<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Response;

class ImageHandler
{
    public function processUploadedImage(UploadedFile $file)
    {
        if (!$file->isValid()) {
            return false;
        }
        
        if (!file_exists($file->getPathname())) {
            return false;
        }
        
        $imageContent = file_get_contents($file->getPathname());
        if ($imageContent === false) {
            return false;
        }
        
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $imageContent);
        rewind($stream);
        
        return $stream;
    }

    public function createImageResponse($imageResource): ?Response
    {
        $imageContent = stream_get_contents($imageResource);
        if ($imageContent === false) {
            return null;
        }
        
        $response = new Response($imageContent);
        $contentType = $this->detectContentType($imageContent);
        $response->headers->set('Content-Type', $contentType);
        
        return $response;
    }

    private function detectContentType(string $imageContent): string
    {
        $contentType = 'image/svg+xml';

        if (str_starts_with($imageContent, "\x89PNG")) {
            $contentType = 'image/png';
        }
        elseif (str_starts_with($imageContent, "\xff\xd8\xff")) {
            $contentType = 'image/jpeg';
        }
        
        return $contentType;
    }
} 