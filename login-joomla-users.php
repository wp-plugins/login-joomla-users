<?php
/*
Plugin Name: Login Joomla Users
Description: Login users migrated from Joomla
Version: 0.0.1
Author: 247wd
*/

if( ! function_exists( 'wp_check_password' ) )
{
    function wp_check_password($password, $hash, $user_id = '') {
        global $wp_hasher;
    
        // If the hash is still md5...
        if ( strlen($hash) <= 32 ) {
            $check = hash_equals( $hash, md5( $password ) );
            if ( $check && $user_id ) {
                // Rehash using new hash.
                wp_set_password($password, $user_id);
                $hash = wp_hash_password($password);
            }
    
            /**
             * Filter whether the plaintext password matches the encrypted password.
             *
             * @since 2.5.0
             *
             * @param bool   $check    Whether the passwords match.
             * @param string $password The plaintext password.
             * @param string $hash     The hashed password.
             * @param int    $user_id  User ID.
             */
            return apply_filters( 'check_password', $check, $password, $hash, $user_id );
        }
        
        // Check if password is migrated Joomla password
        if ( 65 == strlen( $hash ) )
        {
            $hashparts = explode( ':', $hash );
            if ( isset( $hashparts[0] ) && isset( $hashparts[1] ) )
            {
                $joomlahash = md5( $password . $hashparts[1] ) . ':' . $hashparts[1];
                $check = hash_equals( $hash, $joomlahash );
                if ( $check && $user_id )
                {
                    // Rehash using new hash.
                    wp_set_password( $password, $user_id );
                    $hash = wp_hash_password( $password );
                }
                return apply_filters( 'check_password', $check, $password, $hash, $user_id );
            }
        }
    
        // If the stored hash is longer than an MD5, presume the
        // new style phpass portable hash.
        if ( empty($wp_hasher) ) {
            require_once( ABSPATH . WPINC . '/class-phpass.php');
            // By default, use the portable hash from phpass
            $wp_hasher = new PasswordHash(8, true);
        }
    
        $check = $wp_hasher->CheckPassword($password, $hash);
    
        /** This filter is documented in wp-includes/pluggable.php */
        return apply_filters( 'check_password', $check, $password, $hash, $user_id );
    }
}