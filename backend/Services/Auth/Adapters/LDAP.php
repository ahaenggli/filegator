<?php

/*
 * This file is part of the FileGator package.
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

/**
 * @codeCoverageIgnore
 */
class LDAP implements Service, AuthInterface
{
    const SESSION_KEY = 'LDAP_auth';
    const GUEST_USERNAME = 'guest';

    protected $session;
    protected $private_repos = false;
    protected $ldap_server;
    protected $ldap_bindDN;
    protected $ldap_bindPass;
    protected $ldap_baseDN;
    protected $ldap_filter;
    protected $ldap_userFieldMapping;

    protected $TokenDB;
    protected $RepoPath;

    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    public function init(array $config = [])
    {
        if(!empty($config['TokenDB']))
          @$this->TokenDB = new \SQLite3($config['TokenDB']);
          @$this->RepoPath =$config['RepoPath'];

        if(!isset($config['ldap_server']) || empty($config['ldap_server']))
            throw new \Exception('config ldap_server missing');

        if (!extension_loaded('ldap')) throw new \Exception('ldap extension missing');

        if($connect=ldap_connect($config['ldap_server'])){
                ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
                $this->private_repos = $config['private_repos'];
                $this->ldap_server = $config['ldap_server'];
                $this->ldap_bindDN = $config['ldap_bindDN'];
                $this->ldap_bindPass = $config['ldap_bindPass'];
                $this->ldap_baseDN = $config['ldap_baseDN'];
                $this->ldap_filter = $config['ldap_filter'];
                $this->ldap_userFieldMapping = $config['ldap_userFieldMapping'];
        }else {
                @ldap_close($connect);
                throw new \Exception('could not connect to domain');
         }

        @ldap_close($connect);
    }

    public function user(): ?User
    {
        if(isset($_GET['uploadlink'])) return null;
        if(isset($_GET['download']))   return null;
        return $this->session ? $this->session->get(self::SESSION_KEY, null) : null;
    }

    public function authenticate($username, $password): bool
    {
        $all_users = $this->getUsers();

        foreach ($all_users as &$u) {
            if ($u['username'] == $username && $this->verifyPassword($u['userDN'], $password)) {
                $user = $this->mapToUserObject($u);
                $this->store($user);
                return true;
            }
        }

        return false;
    }

    public function forget()
    {
        return $this->session->invalidate();
    }

    public function store(User $user)
    {
        return $this->session->set(self::SESSION_KEY, $user);
    }

    public function update($username, User $user, $password = ''): User
    {
        return new User(); // not used
    }

    public function add(User $user, $password): User
    {
        return new User(); // not used
    }

    public function delete(User $user)
    {
        return true; // not used
    }

    public function find($username): ?User
    {
        foreach ($this->getUsers() as $user) {
            if ($user['username'] == $username) {
                return $this->mapToUserObject($user);
            }
        }

        return null;
    }



    function uploadlinks($key){
        $db = $this->TokenDB;
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
        $db = $this->TokenDB;
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
        $guest = $this->find(self::GUEST_USERNAME);

        if (!$guest || !$guest->isGuest()) {
            $guest = new User();
            $guest->setUsername('guest');
            $guest->setName('Guest');
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

        return $guest;
    }

    public function allUsers(): UsersCollection
    {
        $users = new UsersCollection();

        foreach ($this->getUsers() as $user) {
            $users->addUser($this->mapToUserObject($user));
        }

        return $users;
    }

    protected function mapToUserObject(array $user): User
    {
        $new = new User();
        $new->setUsername($user['username']);
        $new->setName($user['name']);
        $new->setRole($user['role']);
        $new->setHomedir($user['homedir']);
        $new->setPermissions($user['permissions'], true);
        return $new;
    }

    protected function getUsers(): array
    {
            $ldapConn = @ldap_connect($this->ldap_server);
            if (!$ldapConn) throw new \Exception('Cannot Connect to LDAP server');
            @ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);

            $ldapBind = @ldap_bind($ldapConn, $this->ldap_bindDN,$this->ldap_bindPass);
            if (!$ldapBind) throw new \Exception('Cannot Bind to LDAP server: Wrong credentials?');

            // search the LDAP server for users
            $ldapSearch  = @ldap_search($ldapConn, $this->ldap_baseDN, $this->ldap_filter, ['*']);
            $ldapResults = @ldap_get_entries($ldapConn, $ldapSearch);
            @ldap_close($ldapConn);

            $users = [];

            for ($item = 0; $item < $ldapResults['count']; $item++)
            {
                $user = [];
                $user['username']  = $ldapResults[$item][$this->ldap_userFieldMapping['username']][0];
                $user['name']      = $ldapResults[$item][$this->ldap_userFieldMapping['name']][0];
                $user['role']      = 'user';
                $user['homedir']   = '/';
                $user['permissions']=$this->ldap_userFieldMapping['default_permissions'];
                $user['userDN'] = $ldapResults[$item][$this->ldap_userFieldMapping['userDN']];

                if(is_array($this->ldap_userFieldMapping['admin_usernames']))
                {
                    if(in_array($user['username'], $this->ldap_userFieldMapping['admin_usernames'])) $user['role'] = 'admin';
                }

                // private repositories for each user?
                if ($this->private_repos) {
                    $user->setHomedir('/'.$user['username']);
                }

                // ...but not for admins
                if ($user['role'] == 'admin'){
                    $user['homedir']   = '/';
                    $user['permissions'] = 'read|write|upload|download|batchdownload|zip';
                }

                if(is_array($user) && !empty($user)) $users[] = $user;
            }
        return is_array($users) ? $users : [];
    }

    private function verifyPassword($auth_user, $password)
    {
        if(!isset($this->ldap_server) || empty($this->ldap_server)) return false;
        if(!extension_loaded('ldap')) return false;

        if($connect=ldap_connect($this->ldap_server))
        {
         ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
         if($bind=ldap_bind($connect, $auth_user, $password)){
            @ldap_close($connect);
            return true;
        } else {
            @ldap_close($connect);
            return false;
            }
        }

    @ldap_close($connect);
    return false;
    }
}
