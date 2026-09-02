<?php 

$abc = include('routes.php');

$abc[] = 
  [
        'route' => [
            'POST', '/shareitems', '\Filegator\Controllers\FileControllerWithShare@shareItems',
        ],
        'roles' => [
            'user', 'admin',
        ],
        'permissions' => [
            'read', 'write',
        ],
    ];
    $abc[] = 
  [
        'route' => [
            'POST', '/unshareitems', '\Filegator\Controllers\FileControllerWithShare@unshareItems',
        ],
        'roles' => [
            'user', 'admin',
        ],
        'permissions' => [
            'read', 'write',
        ],
    ];

return $abc;