<?php

/*
 * This file is NOT (yet) part of the FileGator package.
 *
 * (c) Adriano Hänggli <https://github.com/ahaenggli>
 *
 */

namespace Filegator\Services\Auth\Adapters;

use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\Auth\User;
use Filegator\Services\Auth\UsersCollection;
use Filegator\Services\Service;

use Filegator\Services\Session\SessionStorageInterface as Session;
use Filegator\Container\Container as Container;

/**
 * @codeCoverageIgnore
 */
class DynamicAuthWithSharedLinks implements Service, AuthInterface
{
    protected $anonymous_name = 'guest';
    protected $session;
    protected $container;
    protected $auth;

    protected $FileDB;
    protected $RepoPath;
    
    public function __construct(Session $session, Container $container)
    {
        $this->session = $session;
        $this->container = $container;
    }

    public function init(array $config = [])
    {

        if(empty($config['handler']))
            throw new \Exception('config ldap_server missing');

        if(!empty($config['FileDB']))
            @$this->FileDB = new \SQLite3($config['FileDB']);

        if(!empty($config['anonymous_name']))
            $this->anonymous_name = $config['anonymous_name'];

        @$this->RepoPath =$config['RepoPath'];

        $key = 'DynamicAuthWithSharedLinks';

        $this->container->set($key, $this->container->get($config['handler']));
        $this->auth = $this->container->get($key);
        $this->auth->init(isset($config) ? $config : []);
    }

    public function user(): ?User
    {
        if(isset($_GET['uploadlink']) || isset($_GET['download'])) return null;
        return $this->auth->user();
    }

    function uploadlinks($key){
        $db = $this->FileDB;
        $array = [];
        $stmt = $db->prepare('select * from links where type="u" and key= :pfad;');
        $stmt->bindValue(':pfad', $key, \SQLITE3_TEXT);
        $ret = $stmt->execute();

        while($row = $ret->fetchArray(SQLITE3_ASSOC) ) {
           if(is_dir($row['value']) && file_exists($row['value'])) $array[$row['key']] = $row['value'];
           else remove_uploadlink($row['key']);
        }

        return $array;
    }

    function downloadlinks($key){
        $db = $this->FileDB;
        $array = [];
        $stmt = $db->prepare('select * from links where type="d" and key= :pfad;');
        $stmt->bindValue(':pfad', $key, \SQLITE3_TEXT);
        $ret = $stmt->execute();

        while($row = $ret->fetchArray(SQLITE3_ASSOC) ) {
           if(is_file($row['value']) && file_exists($row['value'])) $array[$row['key']] = $row['value'];
           else remove_downloadlink($row['key']);
        }

        return $array;
      }


    public function getGuest(): User
    {
        if ((isset($_GET['download']) && !empty($_GET['download'])) || (isset($_GET['uploadlink']) && !empty($_GET['uploadlink']))) {
            $guest = new User();
            $guest->setUsername($this->anonymous_name);
            $guest->setName($this->anonymous_name);
            $guest->setRole('guest');
            $guest->setHomedir('/');
            $guest->setPermissions(['']);

            if(isset($_GET['download']) && !empty($_GET['download'])){
                $download = $this->downloadlinks($_GET['download']);
                if(!empty($download))
                {
                    $guest->setPermissions(['download']);
                    $key = array_keys($download)[0];
                    $val = array_values($download)[0];
                    $val = base64_encode(str_replace(@$this->RepoPath, '', $val));

                    if(!isset($_GET['path']))
                    {
                       $http = 'http';
                       if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') $http.='s';
                       $url = $http.'://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'].'&path='.$val.'&r=/download';
                       header('LOCATION: '.$url);
                       die();
                    }
                }
            }

            if(isset($_GET['uploadlink']) && !empty($_GET['uploadlink'])){
                $uploadlink = $this->uploadlinks($_GET['uploadlink']);
                if(!empty($uploadlink))
                {
                    $key = array_keys($uploadlink)[0];
                    $val = array_values($uploadlink)[0];
                    $val = str_replace(@$this->RepoPath, '', $val);
                    $guest->setHomedir($val);
                    $guest->setPermissions(['read', 'write', 'upload']);
                }
            }

            return $guest;
        }

        return $this->auth->getGuest();
    }

    public function authenticate($username, $password): bool
    {
        return $this->auth->authenticate($username, $password);
    }

    public function forget()
    {
        return $this->auth->forget();
    }

    public function store(User $user)
    {
        return $this->auth->store($user);
    }

    public function update($username, User $user, $password = ''): User
    {
        return $this->auth->update($username, $user, $password);
    }

    public function add(User $user, $password): User
    {
        return $this->auth->add($user, $password);
    }

    public function delete(User $user)
    {
        return $this->auth->delete($user);
    }

    public function find($username): ?User
    {
        return $this->auth->find($username);
    }

    public function allUsers(): UsersCollection
    {
        return $this->auth->allUsers();
    }

    protected function mapToUserObject(array $user): User
    {
        return $this->auth->mapToUserObject($user);
    }

    protected function getUsers(): array
    {
        return $this->auth->getUsers();
    }

    private function verifyPassword($auth_user, $password)
    {
        return $this->auth->verifyPassword($auth_user, $password);
    }

}
