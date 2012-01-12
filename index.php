<?php

require_once __DIR__ . DIRECTORY_SEPARATOR . 'lib/interface/crypt.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'lib/exception/key.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'lib/exception/salt.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'lib/exception/signature.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'lib/crypt.php';

$data_raw = 'Integer mi non augue.
Sed eget elit lectus nulla massa, nonummy auctor ligula.
Proin orci.
Nullam at ipsum dolor sit amet nunc.
Sed ornare lorem. Cras sit amet, est.
Lorem ipsum dolor sit amet, elementum dui.
In mauris sed ante.
Donec nec augue.
Vestibulum euismod quam placerat augue.
Duis non nibh.
Morbi id pharetra sem luctus et ultrices tincidunt, mi at lorem sapien, tempus vehicula, dui lectus urna augue, ullamcorper libero nec felis.
Morbi scelerisque id, pretium pellentesque.
Proin imperdiet sagittis, metus imperdiet lectus vulputate aliquam pharetra leo.
Donec pede.
Vestibulum at ipsum.
Lorem ipsum vel pede.';
print_r($data_raw);
print '<br />';
$key = 'yxf8fCS5Zq7Fnhjhnp0Su8NcM5d3RRs4';
$salt = '{ErlA(J058s5GCx#ER=fX0H>50ePV7';

$crypt = Crypt::instance(array('key' => $key, 'salt' => $salt));
$data_encrypted = $crypt->encrypt($data_raw);
$data_decrypted = $crypt->decrypt($data_encrypted);

print_r($data_decrypted);
