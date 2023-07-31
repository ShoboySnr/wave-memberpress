<?php
// Exit if accessed directly
namespace WPBROS\WAVE_MP;

if (!defined('ABSPATH')) {
    die('You are not allowed to call this page directly.');
}

class Flutterwave {
    
    /**
     * Constructor
     */
    public function __construct() {
        // Add Gateway Path
        add_filter('mepr-gateway-paths', array($this, 'add_mepr_gateway_paths'));
        
        // Add Option Scripts
        add_action('mepr-options-admin-enqueue-script', array($this, 'add_options_admin_enqueue_script'));
    }
    
    /**
     * Add Flutterwave to gateway path
     *
     */
    public  function add_mepr_gateway_paths($tabs) {
        array_push($tabs, WPBROS_WAVE_MP_PATH);
        return $tabs;
    }
    
    
    public static function add_options_admin_enqueue_script($hook)
    {
        if ($hook == 'memberpress_page_memberpress-options') {
            wp_enqueue_script(
                'wpbros-wave-mp-js',
                WPBROS_WAVE_MP_ASSET_URL . 'js/admin_options.js',
                array(
                    'jquery',
                )
            );
            
            wp_enqueue_style('wpbros-wave-mp-css',
                WPBROS_WAVE_MP_ASSET_URL . 'css/admin.css',
                array(),
            );
            return $hook;
        }
    }
}