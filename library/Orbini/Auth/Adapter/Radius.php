<?php
/**
 * Orbini Auth Adapter Radius
 *
 * @category   Auth
 * @package    Orbini
 * @copyright  Copyright (c) 2014 MT4 Software Studio
 * @license    http://opensource.org/licenses/MIT The MIT License
 * @author Felipe Weckx <felipe@weckx.net>
 */

/**
 * @see Zend_Auth_Adapter_Interface
 */
require_once 'Zend/Auth/Adapter/Interface.php';

/**
 * @see Zend_Auth_Result
 */
require_once 'Zend/Auth/Result.php';

/**
 * Adapter to perfom authentication on RADIUS servers. Uses the PECL radius
 * extension.
 *
 * @author Felipe Weckx <felipe@weckx.net>
 */
class Orbini_Auth_Adapter_Radius implements Zend_Auth_Adapter_Interface
{
    /**
     * Maximum number of servers that can be configured
     */
    const MAX_SERVER_COUNT = 10;

    /**
     * Default RADIUS authentication TCP port
     */
    const DEFAULT_PORT = 1812;

    /**
     * Default timeout period
     */
    const DEFAULT_TIMEOUT = 15;

    /**
     * Default maximum authentication attempts
     */
    const DEFAULT_MAXTRIES = 1;

    /**
     * Radius handle
     * @var resource
     */
    protected $_radius = null;

    /**
     * Username
     * @var string
     */
    protected $_username = null;

    /**
     * Password
     * @var string
     */
    protected $_password = null;

    /**
     * Configuration options
     * @var array
     */
    protected $_options = array();

    /**
     * Constructor
     * 
     * @param array  $servers  Array of arrays containing the servers to be used. {@see addServer()}
     * @param string $username The username of the account
     * @param string $password The password of the account
     * @throws Zend_Auth_Adapter_Exception If the radius extension is not loaded or there is an error
     *                                     calling radius_auth_open
     */
    public function __construct($options = array(), $username = null, $password = null)
    {
        if (!extension_loaded('radius')) {
            throw new Zend_Auth_Adapter_Exception('The radius extension is not loaded');
        }

        $this->_radius = radius_auth_open();
        if (!$this->_radius) {
            throw new Zend_Auth_Adapter_Exception('Error creating RADIUS handle');
        }

        $this->_loadOptions($options);
    }

    /**
     * Returns the username of the account or NULL if it is not set
     * @return string|null
     */
    public function getUsername()
    {
        return $this->_username;
    }
    
    /**
     * Sets the username to authenticate
     * @var string $username
     * @return Orbini_Auth_Adapter_Radius Provides fluent interface
     */
    public function setUsername($username)
    {
        $this->_username = $username;
        return $this;
    }

    /**
     * Returns the identity. For compatibility with other adapters. Proxies to {@see getUsername()}
     * @return string
     */
    public function getIdentity()
    {
        return $this->getUsername();
    }
    
    /**
     * Sets the identity. For compatibility with other adapters. Proxies to {@see setUsername()}
     * @var string $identity
     * @return self
     */
    public function setIdentity($identity)
    {
        return $this->setUsername($identity);
    }

    /**
     * Return the password being used to authenticate
     * @return string
     */
    public function getPassword()
    {
        return $this->_password;
    }
    
    /**
     * Sets the password to authenticate
     * @var string $password
     * @return Orbini_Auth_Adapter_Radius Provides fluent interface
     */
    public function setPassword($password)
    {
        $this->_password = $password;
        return $this;
    }

    /**
     * Returns the credential. For compatibility with other adapters. Proxies to {@see getPassword()}
     * @return string
     */
    public function getCredential()
    {
        return $this->getPassword();
    }
    
    /**
     * Sets the credential. For compatibility with other adapters. Proxies to {@see setPassword()}
     * @var string $credential
     * @return self
     */
    public function setCredential($credential)
    {
        return $this->setPassword($credential);
    }

    /**
     * Returns the radius handle. Can be used on the radius_* functions
     * @return resource
     */
    public function getRadius()
    {
        return $this->_radius;
    }
    
    /**
     * Sets the radius handle. This basically overrides all configuration made on the object
     * @var resource $radius
     * @return Orbini_Auth_Adapter_Radius Provides fluent interface
     */
    public function setRadius($radius)
    {
        $this->_radius = $radius;
        return $this;
    }

    /**
     * Return current options
     * @return array 
     */
    public function getOptions()
    {
        return $this->_options;
    }

    /**
     * Adds a RADIUS server to try to authenticate. Up to 10 servers can be specified.
     * @param string  $hostname The hostname or IP address of the server.
     * @param int     $port     The port on which authentication is listening. Usually 1812.
     * @param string  $secret   The shared secret for the server host.
     * @param integer $timeout  Timeout in seconds to wait for a server reply
     * @param integer $maxTries Maximum number of repeated requests before giving up
     * @throws Zend_Auth_Adapter_Exception If the server cannot be added
     */
    public function addServer($hostname, $port = self::DEFAULT_PORT, $secret = null, 
                                $timeout = self::DEFAULT_TIMEOUT, $maxTries = self::DEFAULT_MAXTRIES)
    {
        if (count($this->_options['servers']) == self::MAX_SERVER_COUNT) {
            throw new Zend_Auth_Adapter_Exception('A maximum of ' . self::MAX_SERVER_COUNT . ' can be added.');
        }

        if (!radius_add_server($this->_radius, $hostname, $port, $secret, $timeout, $maxTries)) {
            throw new Zend_Auth_Adapter_Exception('Error adding RADIUS server: ' . radius_strerror($this->_radius));
        }

        $this->_options['servers'][] = array(
            'hostname' => $hostname,
            'port'     => $port,
            'secret'   => $secret,
            'timeout'  => $timeout,
            'maxTries' => $maxTries
        );

        return $this;
    }

    /**
     * Authenticate the configured user
     * 
     * @return Zend_Auth_Result
     */
    public function authenticate()
    {
        //Create RADIUS request
        radius_create_request($this->_radius, RADIUS_ACCESS_REQUEST);

        if ($this->getUsername()) {
            radius_put_attr($this->_radius, RADIUS_USER_NAME, $this->getUsername());
        }

        if ($this->getPassword()) {
            radius_put_attr($this->_radius, RADIUS_USER_PASSWORD, $this->getPassword());
        }

        //Send
        $result = radius_send_request($this->_radius);

        switch($result)
        {
            case RADIUS_ACCESS_ACCEPT:
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $this->getUsername());
            case RADIUS_ACCESS_REJECT:
                return new Zend_Auth_Result(
                    Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID, 
                    $this->getUsername(), 
                    array(radius_strerror($this->_radius))
                );
            default:
                var_dump($result);
                return new Zend_Auth_Result(
                    Zend_Auth_Result::FAILURE_UNCATEGORIZED, 
                    $this->getUsername(), 
                    array(radius_strerror($this->_radius))
                );
        }
    }

    /**
     * Loads an array of options
     * @param  array  $options The array of options in the format:
     *                         array(
     *                             'servers' => array(
     *                                 array(
     *                                     'hostname' => '127.0.0.1', 
     *                                     'port' => 1812, 
     *                                     'secret' => 'mysecret',
     *                                     'timeout' => 10,
     *                                     'maxTries' => 2
     *                                 )
     *                             ),
     *                             'attribs' => array(
     *                                 RADIUS_CHAP_PASSWORD => pack('C', $ident),
     *                                 RADIUS_CHAP_CHALLENGE => 'challenge'
     *                             )
     *                         )
     * @return void
     */
    protected function _loadOptions(array $options)
    {
        $this->_options = array(
            'servers' => array(),
            'attribs' => array()
        );

        if (isset($options['servers'])) {
            foreach ($options['servers'] as $server) {
                if (!is_array($server) || !isset($server['hostname'])) {
                    throw new Zend_Auth_Adapter_Exception('Invalid format on servers configuration');
                }
                $port = isset($server['port']) ? $server['port'] : self::DEFAULT_PORT;
                $secret = isset($server['secret']) ? $server['secret'] : '';
                $timeout = isset($server['timeout']) ? $server['timeout'] : self::DEFAULT_TIMEOUT;
                $maxTries = isset($server['maxTries']) ? $server['maxTries'] : self::DEFAULT_MAXTRIES;

                $this->addServer($server['hostname'], $port, $secret, $timeout, $maxTries);
            }
        }

        if (isset($options['attribs']) && is_array($options['attribs'])) {
            $this->_options['attribs'] = $options['attribs'];
        }
    }
}

