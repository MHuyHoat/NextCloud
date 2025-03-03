<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2023 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\EduSoft\Controller;

use Exception;
use OCA\EduSoft\Services\UserService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;

/**
 * @psalm-import-type Provisioning_APIUserDetails from ResponseDefinitions
 */
class UsersController extends Controller
{
  private $userService;
  public function __construct(UserService  $userService)
  {
	$this->userService = $userService;
  }
  #[NoCSRFRequired]
  #[NoAdminRequired]
  #[PublicPage]
  #[ApiRoute(verb: 'POST', url: '/create-user')]
  public function createUser(
	string $userid,
	string $password = null,
	string $displayName = null,
	string $email = '',
	array $groups = [],
	array $subadmin = [],
	string $quota = '',
	string $language = '',
	string $manager = null,
)  {
	try {
		//code...
	
		
		$response= $this->userService->addUser($userid, $password, $displayName, $email, $groups, $subadmin, $quota, $language, $manager);
		if($response['status']=='error'){
		
				throw new Exception($response['message']);
			
		}
		http_response_code(201);
		echo (json_encode($response));
		die();
	
		
	} catch (Exception $e) {
		http_response_code(500);
		echo (json_encode([
			'status'=>'error',
			'message' => $e->getMessage()]));
		die();
		
	}
  }
  #[NoCSRFRequired]
  #[NoAdminRequired]
  #[PublicPage]
  #[ApiRoute(verb: 'GET', url: '/check-user')]
  public function checkUser(string $userid)  {
	  try {
		//code...
		$existedUser= $this->userService->checkUserExists($userid);
		if($existedUser){
			http_response_code(200);
			echo (json_encode([
				'status'=>'success',
				'message' => 'User exists']));
			die();
		}else{
			http_response_code(404);
			echo (json_encode([
				'status'=>'error',
				'message' => 'User does not exist']));
			die();
		}
	  } catch (\Throwable $e) {
		//throw $th;
		http_response_code(500);
		echo (json_encode([
			'status'=>'error',
			'message' => $e->getMessage()]));
		die();
	  }
  }
  #[NoCSRFRequired]
  #[NoAdminRequired]
  #[PublicPage]
  #[ApiRoute(verb: 'GET', url: '/reset-password')]
  public function resetPassword(string $userid=null,string $password=null,string $jwt=null)  {
	  try {
		if (empty($jwt)) {
			# code...
			throw new Exception("Thiếu jwt", 1);
		}
		if(empty($userid)){	
			throw new Exception("Thiếu userid", 1);
		}
		if(empty($password)){
			throw new Exception("Thiếu password", 1);
		}
		 $this->userService->resetPassword($userid,$password);
		 http_response_code(200);
		 echo (json_encode([
			 'status'=>'success',
			 'message' => 'Password has been reset']));
		 die();
	  } catch (\Throwable $e) {
		http_response_code(500);
		echo (json_encode([
			'status'=>'error',
			'message' => $e->getMessage()]));
		die();
	  }
  }
}
