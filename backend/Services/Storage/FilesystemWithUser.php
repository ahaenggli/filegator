<?php

/*
 * This file is NOT (yet) part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 * some additions by Adriano Hänggli <https://github.com/ahaenggli>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\Storage;

use Filegator\Services\Service;
use League\Flysystem\Filesystem as Flysystem;
use League\Flysystem\Util;
use Filegator\Services\Auth\AuthInterface as AuthInterface;

class FilesystemWithUser extends Filesystem implements Service
{
    protected $separator;

    protected $storage;

    protected $path_prefix;

    protected $user;
    protected $FileDB;
    protected $ShowFileUserOrOwner = false;
    protected $username_RemoveDomains = [];
    protected $auth;

    public function __construct(AuthInterface $auth)
    {
        $this->user = $auth->user() ?: $auth->getGuest();
        $this->auth = $auth;
    }

    public function init(array $config = [])
    {
        $this->separator = $config['separator'];
        $this->username_RemoveDomains = $config['username_RemoveDomains'] ?: [];
        $this->path_prefix = $this->separator;

        $this->ShowFileUserOrOwner = !extension_loaded('SQLite3') ? false : $config['ShowFileUserOrOwner'];
        $this->FileDB = null;

        $adapter = $config['adapter'];

        if ($this->ShowFileUserOrOwner && !empty($config['FileDB'])) {
            $this->FileDB = new \SQLite3($config['FileDB']);
            $sql = <<<EOF
                CREATE TABLE IF NOT EXISTS pfadbesitzer
                (pfad       TEXT  NOT NULL UNIQUE,
                besitzer   TEXT
                );
            EOF;
            $ret = $this->FileDB->exec($sql);
            $sql = <<<EOF
            CREATE TABLE IF NOT EXISTS links
                    (type        CHAR(5),
                    key         TEXT    NOT NULL UNIQUE,
                    value       TEXT     NOT NULL UNIQUE
            );
            EOF;
            $ret = $this->FileDB->exec($sql);
        }

        $config = isset($config['config']) ? $config['config'] : [];
        $this->storage = new Flysystem($adapter(), $config);
    }


    public function createDir(string $path, string $name)
    {
        $destination = $this->joinPaths($this->applyPathPrefix($path), $name);

        while (!empty($this->storage->listContents($destination, true))) {
            $destination = $this->upcountName($destination);
        }
        $this->setUser($destination);
        return $this->storage->createDir($destination);
    }

    public function createFile(string $path, string $name)
    {
        $destination = $this->joinPaths($this->applyPathPrefix($path), $name);

        while ($this->storage->has($destination)) {
            $destination = $this->upcountName($destination);
        }
        $this->setUser($destination);
        $this->storage->put($destination, '');
    }

    public function fileExists(string $path)
    {
        $path = $this->applyPathPrefix($path);

        return $this->storage->has($path);
    }

    public function isDir(string $path)
    {
        $path = $this->applyPathPrefix($path);

        return $this->storage->getSize($path) === false;
    }

    public function copyFile(string $source, string $destination)
    {
        $source = $this->applyPathPrefix($source);
        $destination = $this->joinPaths($this->applyPathPrefix($destination), $this->getBaseName($source));

        while ($this->storage->has($destination)) {
            $destination = $this->upcountName($destination);
        }

        $this->setUser($destination);
        return $this->storage->copy($source, $destination);
    }

    public function copyDir(string $source, string $destination)
    {
        $source = $this->applyPathPrefix($this->addSeparators($source));
        $destination = $this->applyPathPrefix($this->addSeparators($destination));
        $source_dir = $this->getBaseName($source);
        $real_destination = $this->joinPaths($destination, $source_dir);

        while (!empty($this->storage->listContents($real_destination, true))) {
            $real_destination = $this->upcountName($real_destination);
        }

        $contents = $this->storage->listContents($source, true);

        if (empty($contents)) {
            $this->storage->createDir($real_destination);
        }

        foreach ($contents as $file) {
            $source_path = $this->separator . ltrim($file['path'], $this->separator);
            $path = substr($source_path, strlen($source), strlen($source_path));

            if ($file['type'] == 'dir') {
                $this->storage->createDir($this->joinPaths($real_destination, $path));
                $this->setUser($destination);

                continue;
            }

            if ($file['type'] == 'file') {
                $this->storage->copy($file['path'], $this->joinPaths($real_destination, $path));
                $this->setUser($destination);

            }
        }
    }

    public function deleteDir(string $path)
    {
        $this->removeUser($path);
        return $this->storage->deleteDir($this->applyPathPrefix($path));
    }

    public function deleteFile(string $path)
    {
        $this->removeUser($path);
        return $this->storage->delete($this->applyPathPrefix($path));
    }

    public function readStream(string $path): array
    {
        if ($this->isDir($path)) {
            throw new \Exception('Cannot stream directory');
        }

        $path = $this->applyPathPrefix($path);

        return [
            'filename' => $this->getBaseName($path),
            'stream' => $this->storage->readStream($path),
            'filesize' => $this->storage->getSize($path),
        ];
    }

    public function move(string $from, string $to): bool
    {
        $from = $this->applyPathPrefix($from);
        $to = $this->applyPathPrefix($to);

        while ($this->storage->has($to)) {
            $to = $this->upcountName($to);
        }

        $this->removeUser($from);
        $this->setUser($to);
        return $this->storage->rename($from, $to);
    }

    public function rename(string $destination, string $from, string $to): bool
    {
        $from = $this->joinPaths($this->applyPathPrefix($destination), $from);
        $to = $this->joinPaths($this->applyPathPrefix($destination), $to);

        while ($this->storage->has($to)) {
            $to = $this->upcountName($to);
        }
        $this->removeUser($from);
        $this->setUser($to);
        return $this->storage->rename($from, $to);
    }

    public function store(string $path, string $name, $resource, bool $overwrite = false): bool
    {
        $destination = $this->joinPaths($this->applyPathPrefix($path), $name);

        while ($this->storage->has($destination)) {
            if ($overwrite) {
                $this->storage->delete($destination);
            } else {
                $destination = $this->upcountName($destination);
            }
        }
        $this->setUser($destination);
        return $this->storage->putStream($destination, $resource);
    }

    /**
     * Change file permissions one item, with optional recursion
     * 
     * @param string $path
     * @param int $permissions
     * @param null|'all'|'folders'|'files' $recursive
     * @return bool
     * @throws \Exception
     */
    public function chmod(string $path, int $permissions, string $recursive = null)
    {
        $path = $this->applyPathPrefix($path);
        $path = Util::normalizePath($path);
        $adapter = $this->storage->getAdapter();

        $mainResult = $this->chmodItem($path, $permissions);
        if ($recursive !== null) {
            if (method_exists($adapter, 'setRecurseManually')) {
                $adapter->setRecurseManually(true); // this is needed for ftp driver
            }
            $contents = $this->storage->listContents($path, true);
            foreach ($contents as $item) {
                try {
                    if ($item['type'] == 'dir' && ($recursive == 'all' || $recursive == 'folders')) {
                        $this->chmodItem($item['path'], $permissions);
                    }
                    if ($item['type'] == 'file' && ($recursive == 'all' || $recursive == 'files')) {
                        $this->chmodItem($item['path'], $permissions);
                    }
                } catch (\Exception $e) {
                    continue;
                }
            }
        }

        return $mainResult;
    }
    /**
     * Change file permissions for a single item
     * 
     * @param string $path
     * @param int $permissions
     * @return bool
     * @throws \Exception
     */
    public function chmodItem(string $path, int $permissions)
    {
        $adapter = $this->storage->getAdapter();

        switch (get_class($adapter)) {
            case 'League\Flysystem\Adapter\Local':
                $absolutePath = $adapter->applyPathPrefix($path);
                return chmod($absolutePath, octdec($permissions));
                break;
            case 'League\Flysystem\Sftp\SftpAdapter':
                return $adapter->getConnection()->chmod($path, octdec($permissions));
                break;
            case 'Filegator\Services\Storage\Adapters\FilegatorFtp':
                return ftp_chmod($adapter->getConnection(), octdec($permissions), $path) !== false;
                break;
            default:
                throw new \Exception('Selected adapter does not support unix permissions');
                break;
        }
    }

    public function setPathPrefix(string $path_prefix)
    {
        $this->path_prefix = $this->addSeparators($path_prefix);
    }

    public function getSeparator()
    {
        return $this->separator;
    }

    public function getPathPrefix(): string
    {
        return $this->path_prefix;
    }

    public function getDirectoryCollection(string $path, bool $recursive = false): DirectoryCollectionWithUser
    {
        $collection = new DirectoryCollectionWithUser($path);

        // only once for all files in the collection
        $downloadlinks = $this->downloadlinks();
        $uploadlinks = $this->uploadlinks();
        $allUsers = $this->auth->allUsers()->all();


        foreach ($this->storage->listContents($this->applyPathPrefix($path), $recursive) as $entry) {
            // By default only 'path' and 'type' is present

            $name = $this->getBaseName($entry['path']);
            $userpath = $this->stripPathPrefix($entry['path']);
            $dirname = isset($entry['dirname']) ? $entry['dirname'] : $path;
            $size = isset($entry['size']) ? $entry['size'] : 0;
            $timestamp = isset($entry['timestamp']) ? $entry['timestamp'] : 0;
            $permissions = $this->getPermissions($entry);

            $user = $this->getUser($entry['path'], $allUsers);
            $share = null;

            $destination = realpath($this->joinPaths($this->storage->getAdapter()->getPathPrefix(), $this->applyPathPrefix($userpath), $name));

            if ($entry['type'] == 'file')
                $share = array_search($destination, $downloadlinks);
            if ($entry['type'] == 'dir')
                $share = array_search($destination, $uploadlinks);
            if ($share == false)
                $share = null;

            if ($entry['type'] == 'dir' && in_array(substr($name, 0, 1), ['@', '#']))
                continue;

            $collection->addFile($entry['type'], $userpath, $name, $size, $timestamp, $permissions, $user, $share);
        }

        if (!$recursive && $this->addSeparators($path) !== $this->separator) {
            $collection->addFile('back', $this->getParent($path), '..', 0, 0, -1);
        }

        return $collection;
    }

    protected function getPermissions(array $entry): int
    {
        $adapter = $this->storage->getAdapter();
        $path = $entry['path'];

        switch (get_class($adapter)) {
            case 'League\Flysystem\Adapter\Local':
                $path = $adapter->applyPathPrefix($path); // get the full path
                $permissions = substr(sprintf('%o', fileperms($path)), -3);
                return $permissions;
                break;
            case 'League\Flysystem\Sftp\SftpAdapter':
                $stat = $adapter->getConnection()->stat($path);
                return $stat && isset($stat['permissions']) ? substr(decoct($stat['permissions']), -3) : -1;
                break;
            case 'Filegator\Services\Storage\Adapters\FilegatorFtp':
                return isset($entry['permissions']) ? $entry['permissions'] : -1;
                break;
        }
        return -1;
    }

    protected function upcountCallback($matches)
    {
        $index = isset($matches[1]) ? intval($matches[1]) + 1 : 1;
        $ext = isset($matches[2]) ? $matches[2] : '';

        return ' (' . $index . ')' . $ext;
    }

    protected function upcountName($name)
    {
        return preg_replace_callback(
            '/(?:(?: \(([\d]+)\))?(\.[^.]+))?$/',
            [$this, 'upcountCallback'],
            $name,
            1
        );
    }

    private function applyPathPrefix(string $path): string
    {
        if (
            $path == '..'
            || strpos($path, '..' . $this->separator) !== false
            || strpos($path, $this->separator . '..') !== false
        ) {
            $path = $this->separator;
        }

        return $this->joinPaths($this->getPathPrefix(), $path);
    }

    private function stripPathPrefix(string $path): string
    {
        $path = $this->separator . ltrim($path, $this->separator);

        if (substr($path, 0, strlen($this->getPathPrefix())) == $this->getPathPrefix()) {
            $path = $this->separator . substr($path, strlen($this->getPathPrefix()));
        }

        return $path;
    }

    private function addSeparators(string $dir): string
    {
        if (!$dir || $dir == $this->separator || !trim($dir, $this->separator)) {
            return $this->separator;
        }

        return $this->separator . trim($dir, $this->separator) . $this->separator;
    }

    private function joinPaths(string $path1, string $path2): string
    {
        $path1 = $this->escapeDots($path1);
        $path2 = $this->escapeDots($path2);

        if (!$path2 || !trim($path2, $this->separator)) {
            return $this->addSeparators($path1);
        }

        return $this->addSeparators($path1) . ltrim($path2, $this->separator);
    }

    private function getParent(string $dir): string
    {
        if (!$dir || $dir == $this->separator || !trim($dir, $this->separator)) {
            return $this->separator;
        }

        $tmp = explode($this->separator, trim($dir, $this->separator));
        array_pop($tmp);

        return $this->separator . trim(implode($this->separator, $tmp), $this->separator);
    }

    private function getBaseName(string $path): string
    {
        if (!$path || $path == $this->separator || !trim($path, $this->separator)) {
            return $this->separator;
        }

        $tmp = explode($this->separator, trim($path, $this->separator));

        return (string) array_pop($tmp);
    }

    private function escapeDots(string $path): string
    {
        $path = preg_replace('/\\\+\.{2,}/', '', $path);
        $path = preg_replace('/\.{2,}\\\+/', '', $path);
        $path = preg_replace('/\/+\.{2,}/', '', $path);
        $path = preg_replace('/\.{2,}\/+/', '', $path);

        return $path;
    }

    function uploadlinks($key = null)
    {
        $db = $this->FileDB;
        $array = [];
        if ($key == null)
            $ret = $db->query('select * from links where type="u";');
        else {
            $stmt = $db->prepare('select * from links where type="u" and key= :pfad;');
            $stmt->bindValue(':pfad', $key, \SQLITE3_TEXT);
            $ret = $stmt->execute();
        }

        while ($row = $ret->fetchArray(SQLITE3_ASSOC)) {
            if (is_dir($row['value']) && file_exists($row['value']))
                $array[$row['key']] = $row['value'];
            else
                $this->remove_uploadlink($row['key']);
        }

        return $array;
    }
    function add_uploadlink($key, $value)
    {
        $db = $this->FileDB;

        $stmt = $db->prepare('INSERT INTO links (type,key,value)  VALUES (:type, :key, :value);');
        $stmt->bindValue(':key', $key, \SQLITE3_TEXT);
        $stmt->bindValue(':value', $value, \SQLITE3_TEXT);
        $stmt->bindValue(':type', "u", \SQLITE3_TEXT);
        $ret = $stmt->execute();

        if (!$ret) {
            echo $db->lastErrorMsg();
        }
    }
    function remove_uploadlink($key)
    {
        $db = $this->FileDB;
        $stmt = $db->prepare('delete from links where type= :type and key = :key;');
        $stmt->bindValue(':key', $key, \SQLITE3_TEXT);
        $stmt->bindValue(':type', "u", \SQLITE3_TEXT);
        $ret = $stmt->execute();

        if (!$ret) {
            echo $db->lastErrorMsg();
        }
    }

    function downloadlinks($key = null)
    {
        $db = $this->FileDB;
        if ($db == null)
            return [];
        $array = [];
        if ($key == null)
            $ret = $db->query('select * from links where type="d";');
        else {
            $stmt = $db->prepare('select * from links where type="d" and key= :pfad;');
            $stmt->bindValue(':pfad', $key, \SQLITE3_TEXT);
            $ret = $stmt->execute();
        }

        while ($row = $ret->fetchArray(SQLITE3_ASSOC)) {
            if (is_file($row['value']) && file_exists($row['value']))
                $array[$row['key']] = $row['value'];
            else
                $this->remove_downloadlink($row['key']);
        }

        return $array;
    }

    function add_downloadlink($key, $value)
    {
        $db = $this->FileDB;
        $stmt = $db->prepare('INSERT INTO links (type,key,value)  VALUES (:type, :key, :value);');
        $stmt->bindValue(':key', $key, \SQLITE3_TEXT);
        $stmt->bindValue(':value', $value, \SQLITE3_TEXT);
        $stmt->bindValue(':type', "d", \SQLITE3_TEXT);
        $ret = $stmt->execute();
        if (!$ret) {
            echo $db->lastErrorMsg();
        }
    }

    function remove_downloadlink($key)
    {
        $db = $this->FileDB;
        $stmt = $db->prepare('delete from links where type= :type and key = :key;');
        $stmt->bindValue(':key', $key, \SQLITE3_TEXT);
        $stmt->bindValue(':type', "d", \SQLITE3_TEXT);
        $ret = $stmt->execute();
        if (!$ret) {
            echo $db->lastErrorMsg();
        }
    }

    public function shareItem(string $type, string $path)
    {
        if ($this->FileDB == null)
            return;
        //return $this->storage->delete($this->applyPathPrefix($path));

        $userpath = $this->stripPathPrefix($path);
        $name = $this->getBaseName($path);
        $destination = $this->joinPaths($this->storage->getAdapter()->getPathPrefix(), $this->applyPathPrefix($userpath), $name);

        if ($type == 'dir') {
            if (is_dir($destination)) {
                $key = array_search($destination, $this->uploadlinks());
                if ($key === false) {
                    while ($key === false || array_key_exists($key, $this->uploadlinks()))
                        $key = bin2hex(random_bytes(16));
                    $this->add_uploadlink($key, $destination);
                }
                return $key;
                die();
            }
        }

        if ($type == 'file') {
            if (is_file($destination)) {
                $key = array_search($destination, $this->downloadlinks());
                if ($key === false) {
                    while ($key === false || array_key_exists($key, $this->downloadlinks()))
                        $key = bin2hex(random_bytes(16));
                    $this->add_downloadlink($key, $destination);
                }
                return $key;
                die();
            }
        }

        return null;
    }

    public function unshareItem(string $type, string $key)
    {
        if ($this->FileDB == null)
            return;
        if (!isset($key) || empty($key) || $key == null)
            return;

        if ($type == 'dir') {
            if (array_key_exists($key, $this->uploadlinks()))
                $this->remove_uploadlink($key);
        }

        if ($type == 'file') {
            if (array_key_exists($key, $this->downloadlinks()))
                $this->remove_downloadlink($key);
        }

    }

    function setUser($key)
    {
        if (!$this->ShowFileUserOrOwner)
            return;

        $userpath = $this->stripPathPrefix($key);
        $name = $this->getBaseName($key);
        $destination = $this->joinPaths($this->storage->getAdapter()->getPathPrefix(), $this->applyPathPrefix($userpath), $name);

        $stmt = $this->FileDB->prepare('INSERT INTO pfadbesitzer (pfad,besitzer)  VALUES (:key, :val); ');
        $stmt->bindValue(':key', $destination, \SQLITE3_TEXT);
        $stmt->bindValue(':val', $this->user->getUsername(), \SQLITE3_TEXT);
        $result = $stmt->execute();
    }

    private function removeUser($key, $tryDelete = NULL)
    {
        if (!$this->ShowFileUserOrOwner)
            return;

        $stmt = $this->FileDB->prepare('delete from pfadbesitzer where pfad = :key;');
        $stmt->bindValue(':key', $key, \SQLITE3_TEXT);
        $result = $stmt->execute();

        if ($tryDelete === NULL && is_a($this->storage->getAdapter(), 'League\Flysystem\Adapter\Local')) {
            $ret = $this->FileDB->query('select * from pfadbesitzer;');
            while ($row = $ret->fetchArray(SQLITE3_ASSOC)) {
                $destination = realpath($row['pfad']);
                if (!file_exists($destination))
                    $this->removeUser($row['pfad'], false);
            }
        }
    }

    private function getUser($key, $allUsers)
    {
        if (!$this->ShowFileUserOrOwner)
            return null;
        $besitzer = null;

        //$allUsers = $this->auth->allUsers()->all();

        $userpath = $this->stripPathPrefix($key);
        $name = $this->getBaseName($key);
        $destination = $this->joinPaths($this->storage->getAdapter()->getPathPrefix(), $this->applyPathPrefix($userpath), $name);


        if ($this->FileDB != null) {
            $stmt = $this->FileDB->prepare('select * from pfadbesitzer where pfad= :pfad ;');
            $stmt->bindValue(':pfad', $destination, \SQLITE3_TEXT);
            $result = $stmt->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);

            if (isset($row['besitzer']) && !empty($row['besitzer']))
                $besitzer = $row['besitzer'];
        }

        if (
            empty($besitzer) &&
            is_a($this->storage->getAdapter(), 'League\Flysystem\Adapter\Local')
        ) {
            $destination = realpath($destination);
            if (is_dir($destination))
                $destination = realpath($destination);
            $fileowner = fileowner($destination);
            @$besitzer = posix_getpwuid($fileowner)['name'];

            if (empty($besitzer)) {
                foreach ($allUsers as $u => $v) {
                    // $besitzer = $v;
                    if ($v->uidNumber == $fileowner) {
                        $besitzer = $v->getName();
                        break;
                    }
                }
            }
        }


        if (empty($besitzer))
            $besitzer = 'unknown';

        foreach ($this->username_RemoveDomains as $u) {
            $besitzer = str_replace($u, '', $besitzer);
        }
        return $besitzer;
    }

}