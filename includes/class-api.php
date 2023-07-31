<?php

namespace WPBROS\WAVE_MP;
if (!defined('ABSPATH')) {
    die('You are not allowed to call this page directly.');
}


class API
{
    public $plugin_name;
    protected $public_key;
    protected $secret_key;
    
    public function __construct($settings)
    {
        $this->plugin_name = 'Memberpress Flutterwave Gateway Addon';
        $this->secret_key = isset($settings->secret_key) ? $settings->secret_key : '';
        $this->public_key = isset($settings->public_key) ? $settings->public_key : '';
    }
    
    public function send_request(
        $endpoint,
        $body = array(),
        $method = 'post',
        $blocking = true,
        $domain = 'https://api.flutterwave.com/v3/'
    )
    {
        $mepr_options = \MeprOptions::fetch();
        $uri = "{$domain}{$endpoint}";
    
        $args = array(
            'method'        => strtoupper($method),
            'body'          => !empty( $body ) ? wp_json_encode( $body ) : [], // fix for http_build_query() returning error - expects parameter 1 to be array, string given
            'headers'       => $this->get_headers(),
            'blocking'      => $blocking,
            'sslverify'     => $mepr_options->sslverify
        );
    
        $args = \MeprHooks::apply_filters('mepr_flutterwave_request_args', $args);
	
	    error_log("********** FlutterwaveAPI::live_keys:\n" . \MeprUtils::object_to_string($args));
    
        $resp = wp_remote_post( $uri, $args );
	
	    error_log("********** MeprFlutterwaveGateway::live_keys:\n" . \MeprUtils::object_to_string($args));
    
        // If we're not blocking then the response is irrelevant
        // So we'll just return true.
        if ($blocking == false)
            return true;
    
        $json_res = json_decode( wp_remote_retrieve_body( $resp ) );
    
        if (is_wp_error($json_res)) {
            throw new \MeprHttpException(sprintf(__('You had an HTTP error connecting to %s', 'wave-memberpress'), $this->plugin_name));
        } else {
            if(isset($json_res->status)) {
                return $json_res;
            } else {
                throw new \MeprRemoteException(sprintf(__('There was an issue with the payment processor %s. Try again later.', 'wave-memberpress'), $this->plugin_name));
            }
        }
    }
    
    /**
     * Generates the headers to pass to API request.
     */
    public function get_headers()
    {
        return apply_filters(
            'mepr_flutterwave_request_headers',
            [
                'Content-Type'  => 'application/json',
                'Authorization' => "Bearer {$this->secret_key}",
            ]
        );
    }
}