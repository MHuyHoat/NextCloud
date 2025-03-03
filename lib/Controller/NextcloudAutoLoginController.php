<?php

declare(strict_types=1);

namespace OCA\EduSoft\Controller;

use Exception;
use OCA\EduSoft\Helper\Helpers;
use OCA\EduSoft\Helper\LoginChain;
use OCA\EduSoft\Services\UserService as UserServiceEdusoft;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UseSession;

use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\DataResponse;

/**
 * @psalm-suppress UnusedClass
 */
class NextCloudAutoLoginController extends Controller {
		/**
	 * @var \OCP\IConfig
	 */
	private $config;

	/**
	 * @var \OC\User\Manager
	 */
	private $userManager;

	/**
	 * @var \OC\User\Session
	 */
	private $session;

	private $loginChain;

	
	private $helpers;
	private $userSeviceEdusoft;

	public function __construct(
		$AppName,
		\OCP\IRequest $request,
		\OCP\IConfig $config,
		\OC\User\Session $session,
		\OC\User\Manager $userManager,
		LoginChain $loginChain,
		Helpers $helpers,
		UserServiceEdusoft $userSeviceEdusoft

	) {
		parent::__construct($AppName, $request);

		$this->config = $config;
		$this->session = $session;
		$this->userManager = $userManager;
		 $this->loginChain = $loginChain;
		 $this->helpers= $helpers;
		 $this->userSeviceEdusoft= $userSeviceEdusoft;
	}

	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 * @PublicPage
	 */

	/**
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 * @PublicPage
	 */
    #[NoCSRFRequired]
	#[NoAdminRequired]
	#[UseSession]
    #[PublicPage]

	#[OpenAPI(OpenAPI::SCOPE_IGNORE)]
	#[FrontpageRoute(verb: 'GET', url: '/auth')]
	public function auth(string $jwt=null,$userName=null, string $targetPath='/index.php/apps/files/files') {
		try {
			
			if (empty($jwt)) {
				# code...
				throw new Exception("Thiếu jwt", 1);
				
			}
		   
			$decodeJwt = $this->helpers->decodeJwt($jwt); ;
			
			$userName = $decodeJwt['user_name'] ?? null;

			if ($userName === null) {
				// It could be that the JWT token has expired.
				// Redirect to the homepage, which likely redirects to /login
				// and starts the whole flow over again.
				//
				// Hopefully we have better luck next time.
				throw new Exception("Thiếu user_name");
			}
	
			$redirectUrl = '/';
			$targetPathParsed = parse_url($targetPath);
			if ($targetPathParsed !== false) {
				$redirectUrl = $targetPathParsed['path'];
			}
			
			$user = $this->userManager->get($userName);
			 
			if ($user === null) {
				// This could be made friendlier.
				$passWordDefault= $password??"Edusoft@123_$userName";
			  
				$group= $decodeJwt['ma_to_chuc']??null;
				
				$displayName= $decodeJwt['ho_ten']??$userName;
			    $email= $decodeJwt['email']??'';
				$responseCreateUser=$this->userSeviceEdusoft->addUser($userName,$passWordDefault,$displayName,$email,[$group]);

				if($responseCreateUser['status']=='success') $user = $this->userManager->get($userName);
				else {
					http_response_code(500);
					echo json_encode($responseCreateUser);
					die();
				}
				
				

			}else{
				$displayName= $decodeJwt['ho_ten']??$userName;
				$this->userSeviceEdusoft->editUser($userName, 'display', $displayName);
			}
		
	         $backends= $this->userManager->getBackends();
			
			if ($this->session->getUser() === $user) {
				// Already logged in. No need to log in once again.
				return new RedirectResponse($redirectUrl);
			}
	
			if ($this->session->getUser() !== null) {
				// If there is an old session, it would cause our login attempt to not work.
				// We'd be setting some session cookies, but other old ones would remain
				// and the old session would be in use.
				//
				// We work around this by destroying the old session before proceeding.
				$this->session->logout();
			}
	
			$loginData = new \OC\Authentication\Login\LoginData(
				$this->request,
				$userName,
				// Password. It doesn't matter because our custom Login chain
				// doesn't validate it at all.
				'',
				$redirectUrl,
				'', // Timezone
				'', // Timezone offset
			);
	
			// Prepopulate the login request with the user we're logging in.
			// This usually happens in one of the steps of the default LoginChain.
			// For our custom login chain, we pre-populate it.
			$loginData->setUser($user);
		    
			// This is expected to log the user in, updating the session, etc.
			$result = $this->loginChain->process($loginData);
			if (!$result->isSuccess()) {
				// We don't expect any failures, but who knows..
				die('Internal login failure');
			}
        
	
			return new RedirectResponse($redirectUrl);
		} catch (\Throwable $th) {
			//throw $th;
			die( $th->getMessage());
		}
	}
	

}
