<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Controllers;

use Filegator\Config\Config;
use Filegator\Kernel\Request;
use Filegator\Kernel\Response;
use Filegator\Services\Archiver\ArchiverInterface;
use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\Session\SessionStorageInterface as Session;
use Filegator\Services\Storage\Filesystem;

class FileControllerWithShare extends FileController
{
       public function shareItems(Request $request, Response $response)
    {
        $items = $request->input('items', []);
        $r = "";
        foreach ($items as $item) {
            if ($item->type == 'dir') {
                $r.=$this->storage->shareItem('dir', $item->path);
            }
            if ($item->type == 'file') {
                $r.=$this->storage->shareItem('file', $item->path);
            }
        }

        return $response->json($r);
    }
    public function unshareItems(Request $request, Response $response)
    {
        $items = $request->input('items', []);
        $r = "";
        foreach ($items as $item) {
            if ($item->type == 'dir') {
                $r.=$this->storage->unshareItem('dir', $item->share);
            }
            if ($item->type == 'file') {
                $r.=$this->storage->unshareItem('file', $item->share);
            }
        }

        return $response->json($r);
    }

}
