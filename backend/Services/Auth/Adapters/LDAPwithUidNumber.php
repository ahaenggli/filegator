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
use Filegator\Services\Logger\LoggerInterface;
use Monolog\Logger;

/**
 * @codeCoverageIgnore
 */
class LDAPwithUidNumber extends LDAP implements Service, AuthInterface
{
    public function getGuest(): User
    {
        $guest = parent::getGuest();
        $guest->uidNumber = null;
        return $guest;
    }

    protected function mapToUserObject(array $user): User
    {
        $new = parent::mapToUserObject($user);
        $new->uidNumber = $user['uidNumber'];
        return $new;
    }

    protected function getUsers(string $username = null): array
    {
        $ldapConn = @ldap_connect($this->ldap_server);
        if (!$ldapConn)
            throw new \Exception('Cannot Connect to LDAP server');
        @ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
        @ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);

        $ldapBind = @ldap_bind($ldapConn, $this->ldap_bindDN, $this->ldap_bindPass);
        if (!$ldapBind)
            throw new \Exception('Cannot Bind to LDAP server: Wrong credentials?');

        // search the LDAP server for users
        $filter = $this->ldap_filter;
        if (!empty($username))
            $filter = '(&' . $filter . '(' . $this->ldap_userFieldMapping['username'] . '=' . $username . '))';

        $ldapSearch = @ldap_search($ldapConn, $this->ldap_baseDN, $filter, $this->ldap_attributes);

        if (!$ldapSearch) {
            $this->logger->log($filter);
            throw new \Exception('Cannot search LDAP server: Wrong filter?');
        }

        $ldapResults = @ldap_get_entries($ldapConn, $ldapSearch);
        @ldap_close($ldapConn);

        $users = [];

        for ($item = 0; $item < $ldapResults['count']; $item++) {

            $missingAttributes = [];

            // Check if all required attributes are present
            foreach (['username', 'name', 'userDN', 'uidNumber'] as $attribute) {
                if (!isset($ldapResults[$item][$this->ldap_userFieldMapping[$attribute]])) {
                    $missingAttributes[] = '`' . $this->ldap_userFieldMapping[$attribute] . '` as `' . $attribute . '`';
                }
            }
            // if any required attribute is missing, log an info message
            if (!empty($missingAttributes)) {
                $this->logger->log('Missing LDAP attribues: ' . implode(', ', $missingAttributes) . '. Please check the spelling (including upper or lower case).', Logger::WARNING);
            } else {
                $user = [];
                $user['username'] = $ldapResults[$item][$this->ldap_userFieldMapping['username']][0];
                $user['name'] = $ldapResults[$item][$this->ldap_userFieldMapping['name']][0];
                $user['role'] = 'user';
                $user['homedir'] = '/';
                $user['uidNumber'] = $ldapResults[$item][$this->ldap_userFieldMapping['uidNumber']][0];
                $user['permissions'] = $this->ldap_userFieldMapping['default_permissions'];
                $user['userDN'] = $ldapResults[$item][$this->ldap_userFieldMapping['userDN']];

                if (!empty($this->ldap_userFieldMapping['username_AddDomain'])) {
                    if (strpos($user['username'], $this->ldap_userFieldMapping['username_AddDomain']) === false)
                        $user['username'] .= $this->ldap_userFieldMapping['username_AddDomain'];
                }

                if (is_array($this->ldap_userFieldMapping['admin_usernames'])) {
                    if (in_array($user['username'], $this->ldap_userFieldMapping['admin_usernames']))
                        $user['role'] = 'admin';
                }

                // private repositories for each user?
                if ($this->private_repos) {
                    $user['homedir'] = '/' . $user['username'];
                }

                // ...but not for admins
                if ($user['role'] == 'admin') {
                    $user['homedir'] = '/';
                    $user['permissions'] = 'read|write|upload|download|batchdownload|zip|chmod';
                }

                if (is_array($user) && !empty($user))
                    $users[] = $user;
            }
        }
        // print_r($users); // uncomment this line to see all available ldap-login-users
        return is_array($users) ? $users : [];

    }

}
