<?php

use WPBROS\WAVE_MP\API;

if (!defined('ABSPATH')) {
  die('You are not allowed to call this page directly.');
}

class MeprFlutterwaveGateway extends MeprBaseRealGateway
{

  public static $flutterwave_plan_id_str = '_mepr_flutterwave_plan_id';

  /** This will be where the gateway api will interacted from */
  public $flutterwave_api;

  private $verify_transaction_obj;

  /** Used in the view to identify the gateway */
  public function __construct()
  {
    $this->name = __("Flutterwave", 'wave-memberpress');
    $this->icon = WPBROS_WAVE_MP_ASSET_URL . 'images/cards.png';
    $this->desc = __('Pay via Flutterwave', 'wave-memberpress');
    $this->set_defaults();
    $this->key = __('Flutterwave', 'wave-memberpress');

    $this->capabilities = array(
      'process-payments',
      'process-refunds',
      'create-subscriptions',
      'cancel-subscriptions',
      'suspend-subscriptions',
      'resume-subscriptions',
      'send-cc-expirations'
    );

    // Setup the notification actions for this gateway
    $this->notifiers = array(
      'whk' => 'webhook_listener',
      'callback' => 'callback_handler',
    );

    $this->message_pages = array('subscription' => 'subscription_message');
  }


  /**
   *
   */
  protected function set_defaults()
  {
    if (!isset($this->settings)) {
      $this->settings = array();
    }

    $this->settings = (object) array_merge(
      array(
        'gateway' => 'MeprFlutterwaveGateway',
        'id' => $this->generate_id(),
        'label' => '',
        'use_label' => true,
        'icon' => WPBROS_WAVE_MP_ASSET_URL . 'images/flutterwave.png',
        'use_icon' => true,
        'use_desc' => true,
        'email' => '',
        'sandbox' => false,
        'force_ssl' => false,
        'debug' => false,
        'product_id' => 0,
        // set the product id
        'test_mode' => false,
        'secret_hash' => '',
        'api_keys' => array(
          'test' => array(
            'public' => '',
            'secret' => ''
          ),
          'live' => array(
            'public' => '',
            'secret' => ''
          ),
        ),
        'customization_title' => 'My Payment Title',
        'customization_description' => 'My Payment Description',
        'customization_logo_url' => '',
      ),
      (array) $this->settings
    );

    $this->id = $this->settings->id;
    $this->label = $this->settings->label;
    $this->use_label = $this->settings->use_label;
    $this->use_icon = $this->settings->use_icon;
    $this->use_desc = $this->settings->use_desc;

    if ($this->is_test_mode()) {
      $this->settings->public_key = trim($this->settings->api_keys['test']['public']);
      $this->settings->secret_key = trim($this->settings->api_keys['test']['secret']);
    } else {
      $this->settings->public_key = trim($this->settings->api_keys['live']['public']);
      $this->settings->secret_key = trim($this->settings->api_keys['live']['secret']);
    }
  }

  /**
   * Returns boolean ... whether or not we should be sending in test mode or not
   *
   * @return boolean
   */
  public function is_test_mode()
  {
    return (isset($this->settings->test_mode) and $this->settings->test_mode);
  }

  protected static function get_subscr_by_plan_code($plan_code)
  {

  }

  /**
   * @param $settings
   *
   */
  public function load($settings)
  {
    $this->settings = (object) $settings;
    $this->set_defaults();
    $this->flutterwave_api = new API($this->settings);
  }

  /**
   * This method should be used by the class to verify a successful payment by the given
   * the gateway. This method should also be used by any IPN requests or Silent Posts.
   */
  public function callback_handler()
  {
    $this->email_status("Callback Just Came In (" . sanitize_text_field($_SERVER['REQUEST_METHOD']) . "):\n" . MeprUtils::object_to_string($_REQUEST, true) . "\n", $this->settings->debug);

    $mepr_options = MeprOptions::fetch();

    // get the transaction reference from flutterwave callback
    $tx_ref = sanitize_text_field($_REQUEST['tx_ref']);
    $status = sanitize_text_field($_REQUEST['status']);

    $product_object = MeprTransaction::get_one_by_trans_num($tx_ref);

    $this->email_status('Flutterwave Verify Charge Transaction Happening Now - ' . $tx_ref, $this->settings->debug);

    $response = (object) $this->flutterwave_api->send_request("transactions/verify_by_reference?tx_ref={$tx_ref}", array(), 'get');

    $this->verify_transaction_obj = $response;

    // check if transaction was canceled and do not record
    if ('cancelled' == $status) {
      $this->email_status('Flutterwave Transaction Was Cancelled - ' . $tx_ref, $this->settings->debug);

      // show error message ;

      // redirect to the membership product page if the transaction was cancelled
      MeprUtils::wp_redirect(get_permalink($product_object->product_id));
    }

    // check if transaction failed - returned empty object
    if (empty($this->verify_transaction_obj)) {
      $this->record_payment_failure();

      //If all else fails, just send them to their account page
      MeprUtils::wp_redirect($mepr_options->account_page_url('action=subscriptions') . '?message=Payment Failed');
    }

    if (empty($response->data->plan)) {
      $txn = $this->record_payment();
    } else {
      $txn = $this->record_transaction_for_subscription();
    }

    // Redirect to thank you page
    $product = new MeprProduct($txn->product_id);
    $sanitized_title = sanitize_title($product->post_title);
    $query_params = array(
      'membership' => $sanitized_title,
      'trans_num' => $txn->trans_num,
      'membership_id' => $product->ID
    );
    if ($txn->subscription_id > 0) {
      $sub = $txn->subscription();
      $query_params = array_merge($query_params, array('subscr_id' => $sub->subscr_id));
    }

    MeprUtils::wp_redirect($mepr_options->thankyou_page_url(build_query($query_params)));
  }

  /**
   * Used to record a declined payment.
   *
   * @return mixed
   */
  public function record_payment_failure()
  {
    if (!empty($this->verify_transaction_obj)) {
      $transaction_data = $this->verify_transaction_obj->data;

      $txn_ref = $transaction_data->tx_ref;
      $txn_res = MeprTransaction::get_one_by_trans_num($txn_ref);

      if (is_object($txn_res) and isset($txn_res->id)) {
        $txn = new MeprTransaction($txn_res->id);
        $txn->trans_num = $txn_ref;
        $txn->status = MeprTransaction::$failed_str;
        $txn->store();
      } else if(
        isset($this->verify_transaction_obj->data->plan) &&
        $sub = $this::get_subscr_by_plan_id($this->verify_transaction_obj->data->plan)
      ) {
        $first_txn = $sub->first_txn();

        if ($first_txn == false || !($first_txn instanceof MeprTransaction)) {
          $coupon_id = $sub->coupon_id;
        } else {
          $coupon_id = $first_txn->coupon_id;
        }

        $txn = new MeprTransaction();
        $txn->user_id = $sub->user_id;
        $txn->product_id = $sub->product_id;
        $txn->coupon_id = $coupon_id;
        $txn->txn_type = MeprTransaction::$payment_str;
        $txn->status = MeprTransaction::$failed_str;
        $txn->subscription_id = $sub->id;
        $txn->trans_num = $txn_ref;
        $txn->gateway = $this->id;

        $txn->set_gross((float) $transaction_data->amount);

        $txn->store();

        //If first payment fails, Flutterwave will not set up the subscription, so we need to mark it as cancelled in MP
        if ($sub->txn_count == 0) {
          $sub->status = MeprSubscription::$cancelled_str;
        } else {
          $sub->status = MeprSubscription::$active_str;
        }

        $sub->gateway = $this->id;
        $sub->expire_txns(); //Expire associated transactions for the old subscription
        $sub->store();
      } else {
        return false; // Nothing we can do here ... so we outta here
      }


      MeprUtils::send_failed_txn_notices($txn);

      return $txn;
    }

    return false;
  }

  /**
   * Used to record a successful payment by the given gateway. It should have
   * the ability to record a successful payment or a failure. It is this method
   * that should be used when receiving a Flutterwave Webhook.
   */
  public function record_payment()
  {
    $this->email_status("Starting record_payment: " . MeprUtils::object_to_string($_REQUEST), $this->settings->debug);

    if (!empty($this->verify_transaction_obj) && $this->verify_transaction_obj->status == 'success') {
      $transaction_data = $this->verify_transaction_obj->data;

      $transaction = $transaction_data->tx_ref;

      $this->email_status("record_payment: \n" . MeprUtils::object_to_string($transaction_data, true) . "\n", $this->settings->debug);

      $obj = MeprTransaction::get_one_by_trans_num($transaction);

      if (is_object($obj) and isset($obj->id)) {
        $txn = new MeprTransaction;
        $txn->load_data($obj);

        $usr = $txn->user();

        // Just short circuit if the txn has already completed
        if ($txn->status == MeprTransaction::$complete_str) {
          return $txn;
        }

        $txn->status = MeprTransaction::$complete_str;
        // This will only work before maybe_cancel_old_sub is run
        $upgrade = $txn->is_upgrade();
        $downgrade = $txn->is_downgrade();

        $event_txn = $txn->maybe_cancel_old_sub();
        $txn->store();

        $card = $transaction_data->card;
        $this->set_auth_token($usr, $card);

        $this->email_status("Standard Transaction\n" . MeprUtils::object_to_string($txn->rec, true) . "\n", $this->settings->debug);

        $product = $txn->product();

        if ($product->period_type == 'lifetime') {
          if ($upgrade) {
            $this->upgraded_sub($txn, $event_txn);
          } else if ($downgrade) {
            $this->downgraded_sub($txn, $event_txn);
          } else {
            $this->new_sub($txn);
          }

          MeprUtils::send_signup_notices($txn);
        }

        MeprUtils::send_transaction_receipt_notices($txn);

        return $txn;
      }
    }

    return false;
  }

  /**
   * Set the authorization code of the card
   *
   * @param $user
   * @param $auth
   *
   * @return bool|int
   */
  public function set_auth_token($user, $card)
  {
    $card_token = $card->token;
    return update_user_meta($user->ID, 'mepr_flutterwave_card_token', $card_token);
  }

  public function get_auth_token($user)
  {
    return get_user_meta($user->ID, 'mepr_flutterwave_card_token', true);
  }

  /**
   * This method should be used by the class to record a successful subscription transaction from
   * the gateway. This method should also be used by a Silent Posts.
   */
  public function record_transaction_for_subscription()
  {
    $mepr_options = MeprOptions::fetch();

    if (!empty($this->verify_transaction_obj) && $this->verify_transaction_obj->status == 'success') {
      $transaction_data = $this->verify_transaction_obj->data;

      $transaction = $transaction_data->tx_ref;

      // Get Transaction by the transaction reference
      $obj = MeprTransaction::get_one_by_trans_num($transaction);

      // if no subscription exist
      if (!is_object($obj) and !isset($obj->id)) {
        MeprUtils::wp_redirect($mepr_options->account_page_url('action=subscriptions'));
      }

      $txn = new MeprTransaction();
      $txn->load_data($obj);

      if ($txn->status == MeprTransaction::$pending_str && $this->verify_transaction_obj->status == 'success') {
        $txn->status = MeprTransaction::$confirmed_str;
        $txn->store();
      }

      //Reload the txn now that it should have a proper trans_num set
      $txn = new MeprTransaction($txn->id);

      return $txn;
    }
  }

  /** Flutterwave SPECIFIC METHODS **/
  public function webhook_listener()
  {

    $this->email_status("Webhook Just Came In (" . $_SERVER['REQUEST_METHOD'] . "):\n" . MeprUtils::object_to_string($_REQUEST, true) . "\n", $this->settings->debug);

    //retrieve the request's body
    $request = @file_get_contents('php://input');

    if ($this->validate_webhook($request) == true) {
	
      //parse it as JSON
      $request = (object) json_decode($request);
      $obj = $request->data;

      if ($request->event == 'charge.completed') {
        if ($obj->status == 'successful') {
          $this->email_status("###Event: {$request->event}\n" . MeprUtils::object_to_string($request, true) . "\n", $this->settings->debug);

          if (!isset($obj->id)) {
            return;
          }

          $trans_id = $obj->id;

          //verify the transaction just one more time to check if its a re-occuring subscription or one time
          $trans_verify = (object) $this->flutterwave_api->send_request("transactions/{$trans_id}/verify", array(), 'get');
	
          // get the transaction
	        $get_transaction = MeprTransaction::get_one_by_trans_num($trans_verify->data->tx_ref);
          
          // check is a transaction has a subscription attached
          if(!empty($get_transaction->subscription_id)) {
            $get_subscription = new MeprSubscription($get_transaction->subscription_id);
            
	          // if the subscription is already confirmed in case of sending multiple hooks twice for the same transaction
	          if($get_subscription->status == MeprSubscription::$active_str) return;

            
            // process to get the plan id in situation when flutterwave response does not contain the plan parameter
            $plan_id = $get_subscription->get_meta('flutterwave_payment_plan_id', true);
            if(!empty($plan_id)) {
	            $trans_verify->data->plan = (int) $plan_id;
            }
	
	          $_REQUEST['recurring_payment_id'] = $get_subscription->subscr_id;
          }
          
          if($trans_verify->status == 'success') {
            
            $this->verify_transaction_obj = $trans_verify;
            
            if(isset($trans_verify->data->plan)) {
              return $this->record_subscription_payment();
            }

            // Record subscription for an instant charge
            return $this->record_payment();
          }

          
        } else if ($obj->status == 'failed') {
          return $this->record_payment_failure();
        }

      } else if ($request->event == 'subscription.cancelled') {
        return $this->record_cancel_subscription();
      }
    }
  }

  /**
   * Validate Webhook Signature
   *
   * @param $input
   *
   * @return boolean
   */
  public function validate_webhook($input)
  {
    if(!defined('FLUTTERWAVE_MEMBERPRESS_SECRET_HASH')) {
      error_log("********** MeprFlutterwaveGateway::validate_hook Webhook:FLUTTERWAVE_MEMBERPRESS_SECRET_HASH is defined\n" . MeprUtils::object_to_string($input));
      return false;
    }

    $secret_hash = FLUTTERWAVE_MEMBERPRESS_SECRET_HASH;

    $header_name = 'verif-hash';

    $verif_secret_hash = $_SERVER["HTTP_" . strtoupper(str_replace("-", "_", $header_name))];

    return $secret_hash == $verif_secret_hash;
  }

  /**
   * This method should be used by the class to record a successful cancellation
   * from the gateway. This method should also be used by any IPN requests or
   * Silent Posts.
   *
   * @return mixed
   */
  public function record_cancel_subscription()
  {
    $plan_id = sanitize_text_field($_REQUEST['recurring_payment_id']) ?? $this->verify_transaction_obj->plan->id;
    if (!empty($plan_id)) {

      $subscription = $this::get_subscr_by_plan_id($plan_id);

      if (!$subscription) {
        return false;
      }

      // if subscription was already cancelled
      if ($subscription->status == MeprSubscription::$cancelled_str) {
        return $subscription;
      }

      $subscription->status = MeprSubscription::$cancelled_str;
      $subscription->store();

      $subscription->limit_reached_actions();

      MeprUtils::send_cancelled_sub_notices($subscription);

      return $subscription;

    }
  }

  public static function get_subscr_by_plan_id($plan_id)
  {
    global $wpdb;
    $mepr_db = new MeprDb();

    $sql = "
SELECT sub.id
FROM {$mepr_db->subscription_meta} AS submeta LEFT JOIN {$mepr_db->subscriptions} AS sub
ON submeta.subscription_id = sub.id
WHERE submeta.meta_key='flutterwave_payment_plan_id' AND submeta.meta_value=%s
ORDER BY sub.id DESC
LIMIT 1
";

    $sql = $wpdb->prepare($sql, $plan_id);

    $sub_id = $wpdb->get_var($sql);

    if ($sub_id) {
      return new MeprSubscription($sub_id);
    } else {
      return false;
    }
  }

  /**
   * Used to send subscription data to a given payment gateway. In gateways
   * which redirect before this step is necessary this method should just be
   * left blank.
   */
  public function process_create_subscription($txn)
  {
    if (isset($txn) and $txn instanceof MeprTransaction) {
      $usr = $txn->user();
      $prd = $txn->product();
    } else {
      throw new MeprGatewayException(__('Payment was unsuccessful, please check your payment details and try again.', 'wave-memberpress'));
    }

    $mepr_options = MeprOptions::fetch();
    $sub = $txn->subscription();

    // Handle Free Trial period
    if ($sub->trial) {
      //Prepare the $txn for the process_payment method
      $txn->set_subtotal($sub->trial_amount);
      $txn->status = MeprTransaction::$pending_str;
      $this->record_trial_payment($txn);
      return $txn;
    }

    error_log("********** MeprFlutterwaveGateway::process_create_subscription Subscription:\n" . MeprUtils::object_to_string($sub));
	
    //get the current plan registered to the subscription
	  $is_payment_plan_id = $this->get_plan_id($sub);
    //is it old or new
    $is_payment_plan_new = !empty($is_payment_plan_id) ? false : true;
    // Get the plan
    $plan = $this->flutterwave_plan($txn->subscription(), $is_payment_plan_new);

    //Reload the subscription now that it should have a token set
    $sub = new MeprSubscription($sub->id);

    // Default to 0 for infinite occurrences
    $total_occurrences = $sub->limit_cycles ? $sub->limit_cycles_num : 0;

    $amount = $txn->total;

    $payment_plan_id = $plan->id;

    $args = MeprHooks::apply_filters('mepr_flutterwave_subscription_args', array(
      'amount' => $amount,
      'tx_ref' => $txn->trans_num,
      'currency' => $mepr_options->currency_code,
      'customer' => array(
        'name' => $usr->last_name . ' ' . $usr->first_name,
        'email' => $usr->user_email,
      ),
      'redirect_url' => $this->notify_url('callback'),
      'customizations' => array(
        'title' => $this->settings->customization_title,
        'description' => $this->settings->customization_description,
        'logo' => $this->settings->customization_logo_url
      ),
      'payment_options' => 'card',
      // Set payment channel to accept only card for subscriptions
      'payment_plan' => $payment_plan_id,
    ), $txn, $sub);

    $this->email_status("process_create_subscription: \n" . MeprUtils::object_to_string($txn) . "\n", $this->settings->debug);

    error_log("********** MeprFlutterwaveGateway::process_create_subscription altered Subscription:\n" . MeprUtils::object_to_string($sub));
    error_log("********** MeprFlutterwaveGateway::process_create_subscription Transaction:\n" . MeprUtils::object_to_string($txn));

    // Initialize a new payment here
    $response = (object) $this->flutterwave_api->send_request('payments', $args);

    if ($response->status !== 'success') {
      return false;
    }

    return MeprUtils::wp_redirect("{$response->data->link}");

  }
	
	/**
	 * @param $sub
	 *
	 * @return mixed
	 */
	public function get_plan_id($sub)
	{
		$meta_plan_code = $sub->token;
		
		if (is_null($meta_plan_code)) {
			return $sub->get_meta('flutterwave_payment_plan_id', true);
		} else {
			return $meta_plan_code;
		}
	}
	
	/**
	 * Originally I thought these should be associated with
	 * our membership objects but now I realize they should be
	 * associated with our subscription objects
	 *
	 * @param $sub
	 * @param false $is_new
	 *
	 * @return object
	 */
	public function flutterwave_plan($sub, $is_new = false)
	{
		try {
			if ($is_new) {
				$flutterwave_plan = $this->create_new_plan($sub);
			} else {
				$plan_id = $this->get_plan_id($sub);
				if (empty($plan_id)) {
					$flutterwave_plan = $this->create_new_plan($sub);
				} else {
					$flutterwave_plan = $this->flutterwave_api->send_request("payment-plans/$plan_id", array(), 'get');
				}
			}
		} catch (Exception $e) {
			// The call resulted in an error ... meaning that
// there's no plan like that so let's create one
			
			// Don't enclose this in try/catch ... we want any errors to bubble up
			$flutterwave_plan = $this->create_new_plan($sub);
		}
		
		return (object) $flutterwave_plan->data;
	}

  /**
   * @param $txn
   *
   * @return mixed
   */
  public function record_trial_payment($txn)
  {
    $sub = $txn->subscription();

    // Update the txn member vars and store
    $txn->txn_type = MeprTransaction::$payment_str;
    $txn->status = MeprTransaction::$complete_str;
    $txn->expires_at = MeprUtils::ts_to_mysql_date(time() + MeprUtils::days($sub->trial_days), 'Y-m-d 23:59:59');
    $txn->store();

    return true;
  }

  /**
   * @param $sub
   *
   * @return object
   */
  public function create_new_plan($sub)
  {
    $mepr_options = MeprOptions::fetch();
    $prd = $sub->product();

    $interval = 'annually';
    // There's no plan like that so let's create one
    if ($sub->period_type == 'weeks') {
      if ($sub->period == 1) {
        $interval = 'weekly';
      } else {
        $period = $sub->period;
        $interval = "every $period weeks";
      }

    } else if ($sub->period_type == 'months') {
      if ($sub->period == 1) {
        $interval = 'monthly';
      } else if ($sub->period == 3) {
        $interval = 'quarterly';
      } else if ($sub->period == 6) {
        $interval = 'bi-anually';
      } else {
        $period = $sub->period;
        $interval = "every $period months";
      }
    } else if ($sub->period_type == 'years') {
      $interval = 'annually';
    }

    $args = MeprHooks::apply_filters('mepr_flutterwave_create_plan_args', array(
      'amount' => $sub->price,
      'interval' => $interval,
      'name' => $prd->post_title,
      'currency' => $mepr_options->currency_code,
    ), $sub);

    // a check for trial period days - should not charge

    $flutterwave_plan = (object) $this->flutterwave_api->send_request('payment-plans', $args);

    $sub->token = $flutterwave_plan->data->plan_token;
    $sub->update_meta('flutterwave_payment_plan_id', $flutterwave_plan->data->id);
    $sub->store();

    return $flutterwave_plan;
  }

  /**
   * Used to record a successful subscription by the given gateway. It should have
   * the ability to record a successful subscription or a failure. It is this method
   * that should be used when receiving a Flutterwave Webhook.
   */
  public function record_create_subscription()
  {
    $mepr_options = MeprOptions::fetch();

    if(isset($this->verify_transaction_obj) && $this->verify_transaction_obj->status == 'success') {
      $sdata = $this->verify_transaction_obj->data;

      error_log("********** MeprFlutterwaveGateway::record_create_subscription sData: \n" . MeprUtils::object_to_string($sdata));

      $plan_id = $this->verify_transaction_obj->plan;
      $sub = $this::get_subscr_by_plan_id($plan_id);
      if (!$sub) {
        return false;
      }

      error_log("********** MeprFlutterwaveGateway::record_create_subscription Subscription: \n" . MeprUtils::object_to_string($sub));

      $sub->status    = MeprSubscription::$active_str;
      $sub->subscr_id = $sdata->subscription_code;

      $card = $this->get_card($sdata);
      if(!empty($card)) {
        $expiry = explode('/', $card->expiry);
        $sub->cc_exp_month = $expiry[0];
        $sub->cc_exp_year  = $expiry[1];
        $sub->cc_last4     = $card->last_4digits;
      }

      $sub->created_at = gmdate('c');
      $sub->store();

      $sub_verify = (object) $this->flutterwave_api->send_request("subscriptions?transaction_id={$this->verify_transaction_obj->data->id}", array(), 'get');
      if(!empty($sub_verify->data[0]) && $sub_verify->status == 'success') {
        $flutterwave_sub_id = $sub_verify->data[0]->id;
        $flutterwave_customer_id = $sub_verify->data[0]->customer->id;
        $flutterwave_customer_email_address = $sub_verify->data[0]->customer->customer_email;
        
        $sub->update_meta('flutterwave_subscription_id', $flutterwave_sub_id);
        $sub->update_meta('flutterwave_customer_id', $flutterwave_customer_id);
        $sub->update_meta('flutterwave_customer_email_address', $flutterwave_customer_email_address);
      }

      // This will only work before maybe_cancel_old_sub is run
      $upgrade   = $sub->is_upgrade();
      $downgrade = $sub->is_downgrade();

      $event_txn = $sub->maybe_cancel_old_sub();

      $txn = $sub->first_txn();

      if ($txn == false || !($txn instanceof MeprTransaction)) {
        $txn = new MeprTransaction();
        $txn->user_id = $sub->user_id;
        $txn->product_id = $sub->product_id;
      }

      $old_total = $txn->total;

      // If no trial or trial amount is zero then we've got to make
      // sure the confirmation txn lasts through the trial
      if (!$sub->trial || ($sub->trial && $sub->trial_amount <= 0.00)) {
        $trial_days      = ($sub->trial) ? $sub->trial_days : $mepr_options->grace_init_days;
        $txn->status     = MeprTransaction::$confirmed_str;
        $txn->txn_type   = MeprTransaction::$subscription_confirmation_str;
        $txn->expires_at = MeprUtils::ts_to_mysql_date(time() + MeprUtils::days($trial_days), 'Y-m-d 23:59:59');
        $txn->set_subtotal(0.00); // Just a confirmation txn
        $txn->store();
      }

      $txn->set_gross($old_total); // Artificially set the subscription amount

      if ($upgrade) {
        $this->upgraded_sub($sub, $event_txn);
      } else if ($downgrade) {
        $this->downgraded_sub($sub, $event_txn);
      } else {
        $this->new_sub($sub, true);
      }

      //Reload the txn now that it should have a proper trans_num set
      $txn = new MeprTransaction($txn->id);

      MeprUtils::send_signup_notices($txn);

      return array('subscription' => $sub, 'transaction' => $txn);
    }

    return false;
  }

  /**
   * Used to record a successful recurring payment by the given gateway. It
   * should have the ability to record a successful payment or a failure. It is
   * this method that should be used when receiving a Flutterwave Webhook.
   */
  public function record_subscription_payment()
  {
    if (!empty($this->verify_transaction_obj) && $this->verify_transaction_obj->status == 'success') {
      $transaction_data = $this->verify_transaction_obj->data;

      $transaction = $transaction_data->tx_ref;
	
	    if(isset($transaction_data->auth_model) && $transaction_data->auth_model == 'noauth') {
		    return $this->record_subscription_invoice($transaction_data);
	    }

      error_log("********** MeprFlutterwaveGateway::record_subscription_payment sData: \n" . MeprUtils::object_to_string($transaction_data));

      return $this->record_subscription_charge($transaction_data);
    }

    return false;
  }

  public function record_subscription_charge($transaction_data)
  {
    error_log("********** MeprFlutterwaveGateway::record_subscription_charge Charge: \n" . MeprUtils::object_to_string($transaction_data));

    // Make sure there's a valid subscription for this request and this payment hasn't already been recorded
    $plan_id = $this->verify_transaction_obj->data->plan;
    if(
      !($sub = $this::get_subscr_by_plan_id($plan_id)) && MeprTransaction::txn_exists($this->verify_transaction_obj->data->tx_ref)) {
        return false;
      }

      error_log("********** MeprFlutterwaveGateway::record_subscription_charge Subscription: \n" . MeprUtils::object_to_string($sub));

      //If this isn't for us, bail
      if ($sub->gateway != $this->id) {
        return false;
      }

      $txn = $sub->first_txn();

      error_log("********** MeprFlutterwaveGateway::record_subscription_charge Transaction: \n" . MeprUtils::object_to_string($txn));
      
      if ($txn == false || !($txn instanceof MeprTransaction)) {
        $coupon_id = $sub->coupon_id;
      } else {
        $coupon_id = $txn->coupon_id;
      }

      $this->email_status(
        "record_subscription_charge:" .
          "\nSubscription: " . MeprUtils::object_to_string($sub) .
          "\nTransaction: " . MeprUtils::object_to_string($txn),
        $this->settings->debug
      );
      
      $txn->user_id    = $sub->user_id;
      $txn->product_id = $sub->product_id;
      $txn->status     = MeprTransaction::$complete_str;
      $txn->coupon_id  = $coupon_id;
      $txn->trans_num  = $transaction_data->tx_ref;
      $txn->gateway    = $this->id;
      $txn->subscription_id = $sub->id;

      $txn->set_gross((float) $transaction_data->amount);

      $txn->store();

      $sub_verify = (object) $this->flutterwave_api->send_request("subscriptions?transaction_id={$this->verify_transaction_obj->data->id}", array(), 'get');
      if(!empty($sub_verify->data[0]) && $sub_verify->status == 'success') {
        $flutterwave_sub_id = $sub_verify->data[0]->id;
        $flutterwave_customer_id = $sub_verify->data[0]->customer->id;
        $flutterwave_customer_email_address = $sub_verify->data[0]->customer->customer_email;
        
        $sub->update_meta('flutterwave_subscription_id', $flutterwave_sub_id);
        $sub->update_meta('flutterwave_customer_id', $flutterwave_customer_id);
        $sub->update_meta('flutterwave_customer_email_address', $flutterwave_customer_email_address);
      }

      $usr = $txn->user();

      $this->set_auth_token($usr, $transaction_data->card);

      $sub->status = MeprSubscription::$active_str;

      if ($card = $this->get_card($transaction_data)) {
        $expiry = explode('/', $card->expiry);
        $sub->cc_exp_month = $expiry[0];
        $sub->cc_exp_year  = $expiry[1];
        $sub->cc_last4     = $card->last_4digits;
      }

      $sub->store();

      // If a limit was set on the recurring cycles we need
      // to cancel the subscr if the txn_count >= limit_cycles_num
      // This is not possible natively with Flutterwave so we
      // just cancel the subscr when limit_cycles_num is hit
      $sub->limit_payment_cycles();

      $this->email_status(
        "Subscription Transaction\n" .
          MeprUtils::object_to_string($txn->rec),
        $this->settings->debug
      );

      //Reload the txn
      $txn = new MeprTransaction($txn->id);
      
      MeprUtils::send_transaction_receipt_notices($txn);
      MeprUtils::send_cc_expiration_notices($txn);

      return $txn;
  }


  public function get_card($data) {
    
    if (isset($data->card) && $data->payment_type == 'card') {
      return $data->card;
    }
  }

  /**
   * Used to cancel a subscription by the given gateway. This method should be used
   * by the class to record a successful cancellation from the gateway. This method
   * should also be used by any IPN requests or Silent Posts.
   *
   * We bill the outstanding amount of the previous subscription,
   * cancel the previous subscription and create a new subscription
   */
  public function process_update_subscription($subscription_id)
  {
    // TODO: Implement process_update_subscription() method.
  }

  /** This method should be used by the class to record a successful cancellation
   * from the gateway. This method should also be used by any IPN requests or
   * Silent Posts.
   */
  public function record_update_subscription()
  {
    // TODO: Implement record_update_subscription() method.
  }

  /** Used to suspend a subscription by the given gateway.
   */
  public function process_suspend_subscription($sub_id)
  {
    $subscription = new MeprSubscription($sub_id);

    if (!isset($subscription->id) || (int) $subscription->id <= 0) {
      throw new MeprGatewayException(__('This subscription is invalid.', 'wave-memberpress'));
    }

    $flutterwave_sub_id = $subscription->get_meta('flutterwave_subscription_id', true);

    // Yeah we are deactivating the subscription on flutterwave
    $response = $this->flutterwave_api->send_request("subscriptions/$flutterwave_sub_id/cancel", array(), 'put');

    $_REQUEST['recurring_payment_id'] = $subscription->subscr_id;

    return $this->record_suspend_subscription();
  }

  /**
   * This method should be used by the class to push a refund request to the gateway.
   *
   * @param MeprTransaction $txn
   *
   * @return mixed
   */
  public function process_refund(MeprTransaction $txn)
  {
    $mepr_options = MeprOptions::fetch();

    $_REQUEST['trans_num'] = $txn->trans_num;

    $amount = $txn->amount;

    $args = MeprHooks::apply_filters('mepr_flutterwave_refund_args', array(
      'amount'      => $amount,
      'comment'     => 'Refund Memberpress Transaction'
    ), $txn);

    $refund = (object) $this->flutterwave_api->send_request("transactions/$txn->trans_num/refund", $args);

    $this->email_status("Flutterwave Refund: " . MeprUtils::object_to_string($refund), $this->settings->debug);

    return $this->record_refund();
  }

  /**
   * @return mixed
   */
  public function record_refund()
  {
    $trans_num = $_REQUEST['trans_num'];
    $obj = MeprTransaction::get_one_by_trans_num($trans_num);
    
    if (!is_null($obj) && (int) $obj->id > 0) {
      $txn = new MeprTransaction($obj->id);

      // Seriously ... if txn was already refunded what are we doing here?
      if ($txn->status == MeprTransaction::$refunded_str) {
        return $txn->id;
      }

      $txn->status = MeprTransaction::$refunded_str;
      $txn->store();

      MeprUtils::send_refunded_txn_notices($txn);

      return $txn->id;
    }

    return false;

  }

  /**
   * @param $transaction
   *
   * @return mixed
   */
  public function process_trial_payment($transaction)
  {
    $mepr_options = MeprOptions::fetch();
    $sub = $transaction->subscription();

    // Prepare the $txn for the process_payment method
    $transaction->set_subtotal($sub->trial_amount);
    $transaction->status = MeprTransaction::$pending_str;

    // Attempt processing the payment here
    $this->process_payment($transaction, true);
  }

  /**
   * Used to send data to a given payment gateway. In gateways which redirect
   * before this step is necessary this method should just be left blank.
   */
  public function process_payment($txn, $trial = false)
  {
    if (isset($txn) and $txn instanceof MeprTransaction) {
      $usr = $txn->user();
      $prd = $txn->product();
    } else {
      throw new MeprGatewayException(__('Payment transaction intialization was unsuccessful, please try again.', 'memberpress'));
    }

    $mepr_options = MeprOptions::fetch();

    $amount = $txn->total;

    // Initialize the charge on flutterwave's servers - this will charge the user's card
    $args = MeprHooks::apply_filters('mepr_flutterwave_payment_args', array(
      'amount' => $amount,
      'tx_ref' => $txn->trans_num,
      'currency' => $mepr_options->currency_code,
      'customer' => array(
        'name' => $usr->last_name . ' ' . $usr->first_name,
        'email' => $usr->user_email,
      ),
      'redirect_url' => $this->notify_url('callback'),
      'customizations' => array(
	      'title' => $this->settings->customization_title,
	      'description' => $this->settings->customization_description,
	      'logo' => $this->settings->customization_logo_url
      ),
    ), $txn);

    // Initialize a new payment here
    $response = (object) $this->flutterwave_api->send_request('payments', $args);

    if ($response->status !== 'success') {
      return false;
    }

    return MeprUtils::wp_redirect("{$response->data->link}");
  }

  /**
   * This method should be used by the class to record a successful suspension
   * from the gateway.
   *
   * @return mixed
   */
  public function record_suspend_subscription()
  {
    $subscr_id = sanitize_text_field($_REQUEST['recurring_payment_id']);
    $subscription = MeprSubscription::get_one_by_subscr_id($subscr_id);
    
    if (!$subscription) {
      return false;
    }

     // Seriously ... if sub was already suspended what are we doing here?
    if ($subscription->status == MeprSubscription::$suspended_str) {
      return $subscription;
    }

    $subscription->status = MeprSubscription::$suspended_str;
    $subscription->store();

    MeprUtils::send_suspended_sub_notices($subscription);

    return $subscription;
  }

  /**
   * Used to resume a subscription by the given gateway.
   *
   * @param $subscription_id
   *
   * @return mixed
   */
  public function process_resume_subscription($subscription_id)
  {
    $mepr_options = MeprOptions::fetch();
    MeprHooks::do_action('mepr-pre-flutterwave-resume-subscription', $subscription_id); //Allow users to change the subscription programatically before resuming it
    $subscription = new MeprSubscription($subscription_id);

    $orig_trial        = $subscription->trial;
    $orig_trial_days   = $subscription->trial_days;
    $orig_trial_amount = $subscription->trial_amount;

    if ($subscription->is_expired() and !$subscription->is_lifetime()) {
      $expiring_txn = $subscription->expiring_txn();

      // if it's already expired with a real transaction
      // then we want to resume immediately

      if (
        $expiring_txn != false && $expiring_txn instanceof MeprTransaction &&
        $expiring_txn->status != MeprTransaction::$confirmed_str
      ) {
        $subscription->trial = false;
        $subscription->trial_days = 0;
        $subscription->trial_amount = 0.00;
        $subscription->store();
      }
    } else {
      $subscription->trial = true;
      $subscription->trial_days = MeprUtils::tsdays(strtotime($subscription->expires_at) - time());
      $subscription->trial_amount = 0.00;
      $subscription->store();
    }

    $flutterwave_subscription_id = $subscription->get_meta('flutterwave_subscription_id', true);

    $this->email_status(
      "process_resume_subscription: \n" .
        MeprUtils::object_to_string($subscription) . "\n",
      $this->settings->debug
    );

    $this->flutterwave_api->send_request("subscriptions/$flutterwave_subscription_id/activate", array(), 'put');

    $_REQUEST['recurring_payment_id'] = $subscription->subscr_id;
    return $this->record_resume_subscription();
  }

  /**
   * This method should be used by the class to record a successful resuming of
   * as subscription from the gateway.
   *
   * @return mixed
   */
  public function record_resume_subscription()
  {
    $subscr_id = sanitize_text_field($_REQUEST['recurring_payment_id']);
    $sub = MeprSubscription::get_one_by_subscr_id($subscr_id);

    if (!$sub) {
      return false;
    }

    // Seriously ... if sub was already active what are we doing here?
    if ($sub->status == MeprSubscription::$active_str) {
      return $sub;
    }

    $sub->status = MeprSubscription::$active_str;
    $sub->store();

    //Check if prior txn is expired yet or not, if so create a temporary txn so the user can access the content immediately
    $prior_txn = $sub->latest_txn();
    if ($prior_txn == false || !($prior_txn instanceof MeprTransaction) || strtotime($prior_txn->expires_at) < time()) {
      $txn = new MeprTransaction();
      $txn->subscription_id = $sub->id;
      $txn->trans_num  = $sub->subscr_id . '-' . uniqid();
      $txn->status     = MeprTransaction::$confirmed_str;
      $txn->txn_type   = MeprTransaction::$subscription_confirmation_str;
      $txn->expires_at = MeprUtils::ts_to_mysql_date(time() + MeprUtils::days(1), 'Y-m-d H:i:s');
      $txn->set_subtotal(0.00); // Just a confirmation txn
      $txn->store();
    }

    MeprUtils::send_resumed_sub_notices($sub);

    return $sub;
  }

  /**
   * Used to cancel a subscription by the given gateway. This method should be used
   * by the class to record a successful cancellation from the gateway. This method
   * should also be used by any IPN requests or Silent Posts.
   *
   * @param $subscription_id
   *
   * @return mixed
   */
  public function process_cancel_subscription($subscription_id)
  {
    $subscription = new MeprSubscription($subscription_id);

    if (!isset($subscription->id) || (int) $subscription->id <= 0) {
      throw new MeprGatewayException(__('This subscription is invalid.', 'wave-memberpress'));
    }

    $flutterwave_sub_id = $subscription->get_meta('flutterwave_subscription_id', true);

    // Yeah we are deactivating the subscription on flutterwave
    $response = $this->flutterwave_api->send_request("subscriptions/$flutterwave_sub_id/cancel", array(), 'put');

    $_REQUEST['recurring_payment_id'] = $subscription->get_meta('flutterwave_payment_plan_id', true);

    $this->record_cancel_subscription();
  }

  /**
   * This gets called on the 'init' hook when the signup form is processed ...
   * this is in place so that payment solutions like paypal can redirect
   * before any content is rendered.
   *
   * @param $txn
   *
   * @return mixed
   */
  public function process_signup_form($txn)
  {
    // TODO: Implement process_signup_form() method.
  }

  /**
   * @param $txn
   *
   * @return mixed
   */
  public function display_payment_page($txn)
  {
    // TODO: Implement display_payment_page() method.
  }

  /**
   * This gets called on wp_enqueue_script and enqueues a set of
   * scripts for use on the page containing the payment form
   *
   * @return mixed
   */
  public function enqueue_payment_form_scripts()
  {
    // TODO: Implement enqueue_payment_form_scripts() method.
  }

  /**
   * This gets called on the_content and just renders the payment form
   *
   * @param $amount
   * @param $user
   * @param $product_id
   * @param $txn_id
   *
   * @return mixed
   */
  public function display_payment_form($amount, $user, $product_id, $txn_id)
  {
    $mepr_options = MeprOptions::fetch();
    $prd = new MeprProduct($product_id);
    $coupon = false;

    $txn = new MeprTransaction($txn_id);

    //Artifically set the price of the $prd in case a coupon was used
    if ($prd->price != $amount) {
      $coupon = true;
      $prd->price = $amount;
    }

    $invoice = MeprTransactionsHelper::get_invoice($txn);
    echo $invoice;


    ?>
    <div class="mp_wrapper mp_payment_form_wrapper">
      <div class="mp_wrapper mp_payment_form_wrapper">
        <?php MeprView::render('/shared/errors', get_defined_vars()); ?>
        <form action="" method="post" id="mepr_flutterwave_payment_form" class="mepr-checkout-form mepr-form mepr-card-form"
          novalidate>
          <input type="hidden" name="mepr_process_payment_form" value="Y" />
          <input type="hidden" name="mepr_transaction_id" value="<?php echo $txn->id; ?>" />

          <?php MeprHooks::do_action('mepr-flutteerwave-payment-form', $txn); ?>
          <div class="mepr_spacer">&nbsp;</div>

          <input type="submit" class="mepr-submit" value="<?php _e('Pay Now', 'wave-memberpress'); ?>" />
          <img src="<?php echo admin_url('images/loading.gif'); ?>" style="display: none;" class="mepr-loading-gif" />
          <?php MeprView::render('/shared/has_errors', get_defined_vars()); ?>
        </form>
      </div>
    </div>
    <?php
  }

  /**
   * Validates the payment form before a payment is processed
   *
   * @param $errors
   *
   * @return mixed
   */
  public function validate_payment_form($errors)
  {
    // TODO: Implement validate_payment_form() method.
  }

  /**
   * Displays the form for the given payment gateway on the MemberPress Options page
   *
   * @return mixed
   */
  public function display_options_form()
  {
    $mepr_options = MeprOptions::fetch();

    $test_secret_key = trim($this->settings->api_keys['test']['secret']);
    $test_public_key = trim($this->settings->api_keys['test']['public']);
    $live_secret_key = trim($this->settings->api_keys['live']['secret']);
    $live_public_key = trim($this->settings->api_keys['live']['public']);
    $force_ssl = ($this->settings->force_ssl == 'on' or $this->settings->force_ssl == true);
    $debug = ($this->settings->debug == 'on' or $this->settings->debug == true);
    $test_mode = ($this->settings->test_mode == 'on' or $this->settings->test_mode == true);
    $customization_title = $this->settings->customization_title;
    $customization_description = $this->settings->customization_description;
    $customization_logo_url = $this->settings->customization_logo_url;

    $test_secret_key_str = "{$mepr_options->integrations_str}[{$this->id}][api_keys][test][secret]";
    $test_public_key_str = "{$mepr_options->integrations_str}[{$this->id}][api_keys][test][public]";
    $live_secret_key_str = "{$mepr_options->integrations_str}[{$this->id}][api_keys][live][secret]";
    $live_public_key_str = "{$mepr_options->integrations_str}[{$this->id}][api_keys][live][public]";
    $force_ssl_str = "{$mepr_options->integrations_str}[{$this->id}][force_ssl]";
    $debug_str = "{$mepr_options->integrations_str}[{$this->id}][debug]";
    $test_mode_str = "{$mepr_options->integrations_str}[{$this->id}][test_mode]";
    $customization_title_str = "{$mepr_options->integrations_str}[{$this->id}][customization_title]";
	  $customization_description_str = "{$mepr_options->integrations_str}[{$this->id}][customization_description]";
	  $customization_logo_url_str = "{$mepr_options->integrations_str}[{$this->id}][customization_logo_url]";

    ob_start();
    ?>
    <table class="form-table">
      <tbody>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($test_mode_str); ?>"><?php _e('Test Mode', 'memberpress'); ?></label></th>
          <td><input class="mepr-flutterwave-testmode" data-integration="<?php echo esc_attr($this->id); ?>" type="checkbox"
              name="<?php echo esc_attr($test_mode_str); ?>" <?php echo checked($test_mode); ?> />
          </td>
        </tr>
      </tbody>
    </table>
    <table id="mepr-flutterwave-test-keys-<?php echo $this->id; ?>"
      class="form-table mepr-flutterwave-test-keys mepr-hidden">
      <tbody>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($test_public_key_str); ?>"><?php _e('Test Public Key*:', 'wave-memberpress'); ?></label></th>
          <td><input type="text" class="mepr-auto-trim" name="<?php echo esc_attr($test_public_key_str); ?>"
              value="<?php echo $test_public_key; ?>" /></td>
        </tr>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($test_secret_key_str); ?>"><?php _e('Test Secret Key*:', 'wave-memberpress'); ?></label></th>
          <td><input type="text" class="mepr-auto-trim" name="<?php echo esc_attr($test_secret_key_str); ?>"
              value="<?php echo esc_attr($test_secret_key); ?>" /></td>
        </tr>
      </tbody>
    </table>
    <table id="mepr-flutterwave-live-keys-<?php echo $this->id; ?>" class="form-table mepr-flutterwave-live-keys">
      <tbody>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($live_public_key_str); ?>"><?php _e('Live Public Key*:', 'wave-memberpress'); ?></label></th>
          <td><input type="text" class="mepr-auto-trim" name="<?php echo esc_attr($live_public_key_str); ?>"
              value="<?php echo esc_attr($live_public_key); ?>" /></td>
        </tr>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($live_secret_key_str); ?>"><?php _e('Live Secret Key*:', 'wave-memberpress'); ?></label></th>
          <td><input type="text" class="mepr-auto-trim" name="<?php echo esc_attr($live_secret_key_str); ?>"
              value="<?php echo esc_attr($live_secret_key); ?>" /></td>
        </tr>
      </tbody>
    </table>
    <hr />
    <h2><?php echo __('Payment Customization', 'wave-memberpress'); ?></h2>
    <table class="form-table">
      <tbody>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($customization_title_str); ?>"><?php _e('Title', 'wave-memberpress'); ?></label></th>
          <td><input type="text" class="mepr-auto-trim" name="<?php echo esc_attr($customization_title_str); ?>"
                     value="<?php echo esc_attr($customization_title); ?>" /></td>
        </tr>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($customization_description_str); ?>"><?php _e('Description', 'wave-memberpress'); ?></label></th>
          <td><textarea class="large-text" name="<?php echo esc_attr($customization_description_str); ?>"><?php echo esc_attr($customization_description); ?></textarea></td>
        </tr>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($customization_logo_url_str); ?>"><?php _e('Logo URL', 'wave-memberpress'); ?></label></th>
          <td><input type="text" class="mepr-auto-trim" name="<?php echo esc_attr($customization_logo_url_str); ?>"
                     value="<?php echo esc_attr($customization_logo_url); ?>" /></td>
        </tr>
      </tbody>
    </table>
    <hr />
    <table class="form-table">
      <tbody>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($force_ssl_str); ?>"><?php _e('Force SSL', 'memberpress'); ?></label></th>
          <td><input type="checkbox" name="<?php echo esc_attr($force_ssl_str); ?>" <?php echo checked($force_ssl); ?> />
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="<?php echo esc_attr($debug_str); ?>"><?php _e('Send Debug Emails', 'memberpress'); ?></label></th>
          <td><input type="checkbox" name="<?php echo esc_attr($debug_str); ?>" <?php echo checked($debug); ?> /></td>
        </tr>
        <tr>
          <th scope="row"><label>
              <?php _e('Flutterwave Webhook URL:', 'memberpress'); ?>
            </label></th>
          <td>
            <?php MeprAppHelper::clipboard_input($this->notify_url('whk')); ?>
          </td>
        </tr>
      </tbody>
    </table>
    <div class="callout mepr-flutterwave-callout">
      <div class="callout-header">Please note</div>
      <div class="callout-container">
        <p>
          Fluttewave Webhooks are used to receive notifications about all payment events, for webhooks to work please define Flutterwave webhook secret hash key (FLUTTERWAVE_MEMBERPRESS_SECRET_HASH) as a constant in wp-config.php file.
          For example <code>define('FLUTTERWAVE_MEMBERPRESS_SECRET_HASH', 'your-secret-hash');</code> where <strong>your-secret-hash</strong> is the value of the secret hash field.
          <a href="https://developer.flutterwave.com/docs/integration-guides/webhooks" target="_blank" title="<?php _e('Learn more about Webhooks', 'wave-membership'); ?>">
            <?php _e('Learn more about Webhooks', 'wave-membership'); ?>
          </a>
        </p>
        <hr>
        <p>This plugin supports hourly, daily, weekly, monthly, quarterly, yearly, bi-annually and custom
          subscription plans.
          <a href="https://developer.flutterwave.com/docs/recurring-payments/payment-plans"
            title="<?php _e('Learn more about payment plans', 'wave-memberpress'); ?>" target="_blank">Learn More</a>
        </p>
      </div>
    </div>
      <?php

      echo ob_get_clean();

  }

  /**
   * Validates the form for the given payment gateway on the MemberPress Options page
   *
   * @param $errors
   *
   * @return mixed
   */
  public function validate_options_form($errors)
  {
    $mepr_options = MeprOptions::fetch();

    $testmode = isset($_REQUEST[$mepr_options->integrations_str][$this->id]['test_mode']);
    $testmodestr = $testmode ? 'test' : 'live';

    if (
      !isset($_REQUEST[$mepr_options->integrations_str][$this->id]['api_keys'][$testmodestr]['secret']) ||
      empty($_REQUEST[$mepr_options->integrations_str][$this->id]['api_keys'][$testmodestr]['secret']) ||
      !isset($_REQUEST[$mepr_options->integrations_str][$this->id]['api_keys'][$testmodestr]['public']) ||
      empty($_REQUEST[$mepr_options->integrations_str][$this->id]['api_keys'][$testmodestr]['public'])
    ) {
      $errors[] = __("All Flutterwave API keys must be filled in.", 'wave-memberpress');
    }

    return $errors;

  }

  /**
   * This gets called on wp_enqueue_script and enqueues a set of
   * scripts for use on the front end user account page.
   */
  public function enqueue_user_account_scripts()
  {
  }

  /**
   * Displays the update account form on the subscription account page
   *
   * @param $subscription_id
   * @param array $errors
   * @param string $message
   *
   * @return mixed
   */
  public function display_update_account_form($subscription_id, $errors = array(), $message = "")
  {
    ?>
      <div>
        <div class="mepr_update_account_table">
          <div><strong>
              <?php _e('Update your Credit Card information below', 'wave-memberpress'); ?>
            </strong></div>
          <div class="mp-form-row">
            <p>Flutterwave currently doesn't support changing Credit Card for recurring subscription. To change your card
              details, cancel the current subscription and subscribe again.</p>
          </div>
        </div>
      </div>
      <?php
  }

  /**
   * Validates the payment form before a payment is processed
   *
   * @param array $errors
   *
   * @return mixed
   */
  public function validate_update_account_form($errors = array())
  {
    // TODO: Implement validate_update_account_form() method.
  }

  /**
   * Actually pushes the account update to the payment processor
   *
   * @param $subscription_id
   *
   * @return mixed
   */
  public function process_update_account_form($subscription_id)
  {
    // TODO: Implement process_update_account_form() method.
  }

  /**
   * Returns boolean... whether or not to force ssl in sending requests
   *
   * @return boolean
   */
  public function force_ssl()
  {
    return (isset($this->settings->force_ssl) and ($this->settings->force_ssl == 'on' or $this->settings->force_ssl == true));
  }


  /**
   * Get the renewal base date for a given subscription. This is the date MemberPress will use to calculate expiration dates.
   * Of course this method is meant to be overridden when a gateway requires it.
   */
  public function get_renewal_base_date(MeprSubscription $sub)
  {
    global $wpdb;
    $mepr_db = MeprDb::fetch();

    $q = $wpdb->prepare(
      "
        SELECT e.created_at
          FROM {$mepr_db->events} AS e
         WHERE e.event='subscription-resumed'
           AND e.evt_id_type='subscriptions'
           AND e.evt_id=%d
         ORDER BY e.created_at DESC
         LIMIT 1
      ",
      $sub->id
    );

    $renewal_base_date = $wpdb->get_var($q);
    if (!empty($renewal_base_date)) {
      return $renewal_base_date;
    }

    return $sub->created_at;

  }

  /** Get the default card object from a subscribed customer response */
  public function get_default_card($data, $sub)
  {
    $data = (object) $data; // ensure we're dealing with a stdClass object
    $usr = $sub->user();
    $default_card_token = $this->get_auth_token($usr);

    if (isset($default_card_token)) {
      foreach ($data->authorizations as $authorization) {
        if ($usr->token == $default_card_token && $authorization['channel'] == 'card') {
          return $usr->token;
        }
      }
    }

    return false;
  }

  protected function record_subscription_invoice($transaction_data)
  {
	  $subscr_id = sanitize_text_field($_REQUEST['recurring_payment_id']);
	  // Make sure there's a valid subscription for this request and this payment hasn't already been recorded
	  if (
		  !($sub = MeprSubscription::get_one_by_subscr_id($subscr_id)) && MeprTransaction::txn_exists($transaction_data->tx_ref)
	  ) {
		  return false;
	  }
	
	  //If this isn't for us, bail
	  if ($sub->gateway != $this->id) {
		  return false;
	  }
	
	  $first_txn = $txn = $sub->first_txn();
	
	  if ($first_txn == false || !($first_txn instanceof MeprTransaction)) {
		  $coupon_id = $sub->coupon_id;
	  } else {
		  $coupon_id = $first_txn->coupon_id;
	  }
	
	  $this->email_status(
		  "record_subscription_invoice:" .
		  "\nSubscription: " . MeprUtils::object_to_string($sub, true) .
		  "\nTransaction: " . MeprUtils::object_to_string($txn, true),
		  $this->settings->debug
	  );
	
	  $txn = new MeprTransaction();
	  $txn->user_id    = $sub->user_id;
	  $txn->product_id = $sub->product_id;
	  $txn->status     = MeprTransaction::$complete_str;
	  $txn->coupon_id  = $coupon_id;
	  $txn->trans_num  = $invoice->transaction['reference'] ?? MeprTransaction::generate_trans_num();
	  $txn->gateway    = $this->id;
	  $txn->subscription_id = $sub->id;
    
    $txn->set_gross($transaction_data->amount);
    
	  $txn->store();
	
	  $usr = $txn->user();
	  $card = $transaction_data->card;
   
	  // Set Auth Token for Current User
	  $this->set_auth_token($usr, $card);
	
	  $sub->status = MeprSubscription::$active_str;
	
	  if ($card = $this->get_card($transaction_data)) {
		  $sub->cc_exp_month = $card['exp_month'];
		  $sub->cc_exp_year  = $card['exp_year'];
		  $sub->cc_last4     = $card['last4'];
	  }
	
	  $sub->store();
	
	  // If a limit was set on the recurring cycles we need
	  // to cancel the subscr if the txn_count >= limit_cycles_num
	  // This is not possible natively with Flutterwave so we
	  // just cancel the subscr when limit_cycles_num is hit
	  $sub->limit_payment_cycles();
	
	  $this->email_status(
		  "New Subscription Transaction\n" .
		  MeprUtils::object_to_string($txn->rec, true),
		  $this->settings->debug
	  );
	
	  MeprUtils::send_transaction_receipt_notices($txn);
	  MeprUtils::send_cc_expiration_notices($txn);
	
	  return $txn;
  }
}