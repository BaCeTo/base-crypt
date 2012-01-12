<?php

class Crypt implements Interface_Crypt {

  const MINIMUM_KEY_SIZE = 16;
  const SIGNATURE_SEPARATOR = ':';
  protected $config = array(
    'cypher'      => MCRYPT_RIJNDAEL_256,
    'cypher_dir'  => '',
    'cypher_mode' => MCRYPT_MODE_CBC,
    'mode_dir'    => '',
    'json_assoc'  => TRUE,
    'salt'        => '',
    'key'         => '',
  );

  public function __construct(array $config = NULL) {
    $this->read_config($config);
    return $this;
  }

  public static function instance($config = NULL) {
    static $self;
    if (is_null($self)) {
      $self = new self($config);
    }
    return $self;
  }

  public function encrypt($data = NULL) {
    if (strlen($this->config['key']) < self::MINIMUM_KEY_SIZE) {
      throw new Exception_Key();
    }
    $this->cypher = mcrypt_module_open($this->config['cypher'], $this->config['cypher_dir'], $this->config['cypher_mode'], $this->config['mode_dir']);
    $this->vector = mcrypt_create_iv(mcrypt_enc_get_iv_size($this->cypher), MCRYPT_RAND);
    $key = substr($this->config['key'], 0, mcrypt_enc_get_key_size($this->cypher));
    mcrypt_generic_init($this->cypher, $key , $this->vector);
    $data = json_encode($data) . $this->config['salt'];
    $data = base64_encode($data);
    $data .= self::SIGNATURE_SEPARATOR . $this->signature($data);
    $encrypted = mcrypt_generic($this->cypher, $data);
    return $this->vector . $encrypted;
  }

  public function decrypt($data = NULL) {
    if (strlen($this->config['key']) < self::MINIMUM_KEY_SIZE) {
      throw new Exception_Key();
    }
    $this->cypher = mcrypt_module_open($this->config['cypher'], $this->config['cypher_dir'], $this->config['cypher_mode'], $this->config['mode_dir']);
    $this->vector = substr($data, 0, mcrypt_enc_get_iv_size($this->cypher));
    $data = substr($data, strlen($this->vector), strlen($data));
    $key  = substr($this->config['key'], 0, mcrypt_enc_get_key_size($this->cypher));
    mcrypt_generic_init($this->cypher, $key , $this->vector);
    $data = mdecrypt_generic($this->cypher, $data);
    $data = trim($data);
    list($data, $signature) = explode(self::SIGNATURE_SEPARATOR, $data);
    if ($this->signature($data) !== $signature) {
      throw new Exception_Signature();
    }
    $data = base64_decode($data);
    $raw_data = substr($data, 0, strlen($data) - strlen($this->config['salt']));
    $salt = substr($data, -1 * strlen($this->config['salt']));
    if ($this->config['salt'] !== $salt) {
      throw new Exception_Salt();
    }
    $decrypted = json_decode($raw_data, $this->config['json_assoc']);
    return $decrypted;
  }

  private function signature($data) {
    return sha1($data);
  }

  private function read_config(array $config) {
    foreach ($config as $key => $value) {
      if (array_key_exists($key, $this->config)) {
        $this->config[$key] = $value;
      }
    }
  }
}