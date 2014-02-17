<?php

/**
 * Mollom Form Field.
 *
 * The {@link FormField} which is inserted into your form fields via the 
 * spam protector class.
 *
 * @package mollom
 */

class MollomField extends SpamProtectorField {

	/**
	 * Determines if we should always show captcha on first load, rather than waiting for spam detection to trigger.
	 * The captcha will only be hidden if the current user is exempt from spam detection.
	 * 
	 * @config
	 * @var boolean
	 */
	private static $always_show_captcha = false;
	
	/**
	 * Determines if we should show captchas, even for logged in members.
	 * 
	 * @config
	 * @var boolean
	 */
	private static $force_check_on_members = false;
	
	/**
	 * @var string
	 */
	protected $template = 'MollomField';

	/**
	 * @return string
	 */
	public function getCaptchaAudioFile() {
		return MOLLOM_DIR . '/mollom-captcha-player.swf';
	}

	/**
	 * Returns the captcha url if we need to get it from the user
	 *
	 * @return string
	 */
	public function getCaptcha() {
		if($this->getShowCaptcha()) {
			Requirements::css(MOLLOM_DIR . '/css/mollom.css');

			$result = $this->getMollom()->createCaptcha(array(
				'type' => 'image'
			));

			if(is_array($result)) {
				Session::set('mollom_session_id', $result['id']);

				return $result['url'];
			}
		}

		return null;
	}
	
	/**
	 * Determines if the current user is exempt from spam detection
	 * 
	 * @return boolean True if the user is exempt from spam detection
	 */
	protected function exemptUser() {
		
		// Never show captcha for admins
		if(Permission::check('ADMIN')) {
			return true;
		}

		// Allow logged in members to bypass captcha if allowed
		if(Member::currentUser() && !Config::inst()->get('MollomField', 'force_check_on_members')) {
			return true;
		}
		
		return false;
	}

	/**
	 * Return if we should show the captcha to the user.
	 * 
	 * @return boolean
	 */
	public function getShowCaptcha() {
		
		// If this user is eligible to bypass spam detection, don't show them the recaptcha
		if($this->exemptUser()) {
			return false;
		}
		
		// Show captcha if always requested
		if(Config::inst()->get('MollomField', 'always_show_captcha')) {
			return true;
		}
		
		// If a captcha is requested then we need to redisplay it to the user
		if(Session::get('mollom_captcha_requested')) {
			return true;
		}
		
		// If there are no field mappings, then the only detection mechanism is a captcha
		$hasMapping = $this->getFieldMapping();
		return empty($hasMapping);
	}
	
	/**
	 * @return MollomSpamProtector
	 */
	public function getMollom() {
		if(!$this->_mollom) {
			$this->_mollom  = Injector::inst()->create('MollomSpamProtector');
			$this->_mollom ->publicKey = Config::inst()->get('Mollom', 'public_key');
			$this->_mollom ->privateKey = Config::inst()->get('Mollom', 'private_key');

			if(Config::inst()->get('Mollom', 'dev')) {
				$this->_mollom->server = 'dev.mollom.com';
			}
		}

		return $this->_mollom;
	}

	/**
	 * Validate the captcha information
	 *
	 * @param Validator $validator
	 *
	 * @return boolean
	 */
	public function validate($validator) {	
		
		// Bypass spam detection for eligible users
		if($this->exemptUser()) {
			$this->clearMollomSession();
			return true;
		}
		
		// Map all submitted values to mollom fields
		$mapping = $this->getFieldMapping();
		$data = array();
		foreach($mapping as $formField => $mollomField) {
			$value = $this->form->request->requestVar($formField);
			if(!empty($value)) {
				$data[$mollomField] = $value;
			}
		}

		// Handle existing mollom session
		if($sessionID = Session::get("mollom_session_id")) {
			
			// session ID exists so has been checked by captcha
			$data['id'] = $sessionID;
			$data['solution'] = $this->Value();
			$result = $this->getMollom()->checkCaptcha($data);

			// Present result
			if(is_array($result)) {
				if($result['solved']) {
					$this->clearMollomSession();

					return true;
				} else {
					$this->requestMollom();
					
					$validator->validationError(
						$this->name, 
						_t(
							'MollomCaptchaField.CAPTCHAREQUESTED', 
							"Please answer the captcha question",
							"Mollom Captcha provides words in an image, and expects a user to type them in a textfield"
						), 
						"warning"
					);

					return false;
				}
			}
		} else {
			
			$result = $this->getMollom()->checkContent($data);
			
			// Mollom can do much more useful things.
			// @todo handle profanityScore, qualityScore, sentimentScore, reason
			if(is_array($result)) {
				switch($result['spamClassification']) {
					case 'ham':
						$this->clearMollomSession();

						return true;
				
					case 'unsure':
						$this->requestMollom();

						// we're unsure so request the captcha.
						$validator->validationError(
							$this->name, 
							_t(
								'MollomCaptchaField.CAPTCHAREQUESTED', 
								"Please answer the captcha question",
								"Mollom Captcha provides words in an image, and expects a user to type them in a textfield"
							), 
							"warning"
						);

						return false;
					
					case 'spam':
						$this->clearMollomSession();
						$this->requestMollom();

						$validator->validationError(
							$this->name, 
							_t(
								'MollomCaptchaField.SPAM', 
								"Your submission has been rejected because it was treated as spam.",
								"Mollom Captcha provides words in an image, and expects a user to type them in a textfield"
							), 
							"error"
						);

						return false;
					break;
				}
			}
		}
		
		return true;
	}
	
	/**
	 * @return void
	 */
	private function requestMollom() {
		Session::set('mollom_captcha_requested', true);
	}

	/**
	 * Helper to quickly clear all the mollom session settings. For example 
	 * after a successful post.
	 *
	 * @return void
	 */
	private function clearMollomSession() {
		Session::clear('mollom_session_id');
		Session::clear('mollom_captcha_requested');
	}
}
