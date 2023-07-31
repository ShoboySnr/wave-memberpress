<?php
/**
 * Plugin Name:     MemberPress Flutterwave
 * Plugin URI:      https://mactavis.com
 * Description:     Flutterwave integration for Memberpress
 * Version:         1.0.2
 * Author:          Mactavis
 * Author URI:      https://mactavis.com
 * Developer:       Damilare Shobowale
 * Developer URI:   https://techwithdee.com
 * License:         GPL-2.0+
 * License URI:     http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:     wave-memberpress
 * Domain Path:     /languages
*/

// Exit if accessed directly
if (!defined('ABSPATH')) {
    die('You are not allowed to call this page directly.');
}


// Plugin Root File.
if ( ! defined( 'WPBROS_WAVE_MEMBERPREE_PLUGIN_FILE' ) ) {
    define( 'WPBROS_WAVE_MP_PLUGIN_FILE', __FILE__ );
}

// Plugin Folder Name.
if ( ! defined( 'WPBROS_WAVE_MP_PLUGIN_NAME' ) ) {
    define( 'WPBROS_WAVE_MP_PLUGIN_NAME', 'wave-memberpress' );
}

// Plugin version.
if ( ! defined( 'WPBROS_WAVE_MP_VERSION' ) ) {
    define( 'WPBROS_WAVE_MP_VERSION', '1.0.2' );
}

// Plugin Folder Path.
if ( ! defined( 'WPBROS_WAVE_MP_PLUGIN_DIR' ) ) {
    define( 'WPBROS_WAVE_MP_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}

// Plugin Folder URL.
if ( ! defined( 'WPBROS_WAVE_MP_URL' ) ) {
    define( 'WPBROS_WAVE_MP_URL', plugin_dir_url( __FILE__ ) );
}

// Plugin Path
if ( ! defined( 'WPBROS_WAVE_MP_PATH' ) ) {
    define( 'WPBROS_WAVE_MP_PATH', WP_PLUGIN_DIR . '/' . WPBROS_WAVE_MP_PLUGIN_NAME. '/includes');
}


// define path for assets
if(! defined( 'WPBROS_WAVE_MP_ASSET_URL' ) ) {
    define('WPBROS_WAVE_MP_ASSET_URL', WPBROS_WAVE_MP_URL . 'assets/' );
}

function wpbros_wave_memberpress_loader() {
 
    // Bail if MemberPress is not active
    if ( ! in_array( 'memberpress/memberpress.php', (array) get_option( 'active_plugins', array() ) ) ) return;
    
    require_once WPBROS_WAVE_MP_PLUGIN_DIR . 'includes/class-api.php';
    require_once WPBROS_WAVE_MP_PLUGIN_DIR . 'includes/class-wave.php';
    
    new \WPBROS\WAVE_MP\Flutterwave;
    
    
}
add_action( 'plugins_loaded', 'wpbros_wave_memberpress_loader', 100 );