<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2023 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\EduSoft\Services;

use Exception;
use InvalidArgumentException;
use OC\Authentication\Token\RemoteWipe;
use OC\Group\Group;
use OC\KnownUser\KnownUserService;
use OC\User\Backend;
use OCA\Provisioning_API\ResponseDefinitions;
use OCA\Settings\Mailer\NewUserMailHelper;
use OCA\Settings\Settings\Admin\Users;
use OCP\Accounts\IAccountManager;
use OCP\Accounts\IAccountProperty;
use OCP\Accounts\PropertyDoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\AuthorizedAdminSetting;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSForbiddenException;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Group\ISubAdmin;
use OCP\HintException;
use OCP\IConfig;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IPhoneNumberUtil;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Security\Events\GenerateSecurePasswordEvent;
use OCP\Security\ISecureRandom;
use OCP\User\Backend\ISetDisplayNameBackend;
use Psr\Log\LoggerInterface;


/**
 * @psalm-import-type Provisioning_APIUserDetails from ResponseDefinitions
 */
class UserService extends AUserData
{

	private IL10N $l10n;


	public function __construct(
		IUserManager $userManager,
		IConfig $config,
		IGroupManager $groupManager,
		IUserSession $userSession,
		IAccountManager $accountManager,
		ISubAdmin $subAdminManager,
		IFactory $l10nFactory,
		private IURLGenerator $urlGenerator,
		private LoggerInterface $logger,
		private NewUserMailHelper $newUserMailHelper,
		private ISecureRandom $secureRandom,
		private RemoteWipe $remoteWipe,
		private KnownUserService $knownUserService,
		private IEventDispatcher $eventDispatcher,
		private IPhoneNumberUtil $phoneNumberUtil
	) {
		parent::__construct(
			$userManager,
			$config,
			$groupManager,
			$userSession,
			$accountManager,
			$subAdminManager,
			$l10nFactory
		);
	}

	/**
	 * Get a list of users
	 *
	 * @param string $search Text to search for
	 * @param int|null $limit Limit the amount of groups returned
	 * @param int $offset Offset for searching for groups
	 * @return DataResponse<Http::STATUS_OK, array{users: string[]}, array{}>
	 *
	 * 200: Users returned
	 */
	public function checkUserExists(string $uid): bool{
	   if($this->userManager->userExists($uid)){
		   return true;
	   }else{
		   return false;
	   }
	}
	
	public function getUsers(string $search = '', ?int $limit = null, int $offset = 0): DataResponse
	{

		$user = $this->userSession->getUser();
		$users = [];

		// Admin? Or SubAdmin?
		$uid = $user->getUID();
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($uid);
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($uid);
		if ($isAdmin || $isDelegatedAdmin) {
			$users = $this->userManager->search($search, $limit, $offset);
		} elseif ($subAdminManager->isSubAdmin($user)) {
			$subAdminOfGroups = $subAdminManager->getSubAdminsGroups($user);
			foreach ($subAdminOfGroups as $key => $group) {
				$subAdminOfGroups[$key] = $group->getGID();
			}

			$users = [];
			foreach ($subAdminOfGroups as $group) {
				$users = array_merge($users, $this->groupManager->displayNamesInGroup($group, $search, $limit, $offset));
			}
		}

		/** @var string[] $users */
		$users = array_keys($users);

		return new DataResponse([
			'users' => $users
		]);
	}
    public function resetPassword(string $userId, string $password)
	{
      try {
		//code...
		$user = $this->userManager->get($userId);
		if ($user === null) {
			throw new Exception('User not found', 404);
		}
		$user->setPassword($password);
		return true;
	  } catch (\Throwable $th) {
		throw $th;
		return false;
	  }
	}
	/**
	 * Get a list of users and their details
	 *
	 * @param string $search Text to search for
	 * @param int|null $limit Limit the amount of groups returned
	 * @param int $offset Offset for searching for groups
	 * @return DataResponse<Http::STATUS_OK, array{users: array<string, Provisioning_APIUserDetails|array{id: string}>}, array{}>
	 *
	 * 200: Users details returned
	 */
	#[NoAdminRequired]
	public function getUsersDetails(string $search = '', ?int $limit = null, int $offset = 0): DataResponse
	{
		$currentUser = $this->userSession->getUser();
		$users = [];

		// Admin? Or SubAdmin?
		$uid = $currentUser->getUID();
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($uid);
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($uid);
		if ($isAdmin || $isDelegatedAdmin) {
			$users = $this->userManager->search($search, $limit, $offset);
			$users = array_keys($users);
		} elseif ($subAdminManager->isSubAdmin($currentUser)) {
			$subAdminOfGroups = $subAdminManager->getSubAdminsGroups($currentUser);
			foreach ($subAdminOfGroups as $key => $group) {
				$subAdminOfGroups[$key] = $group->getGID();
			}

			$users = [];
			foreach ($subAdminOfGroups as $group) {
				$users[] = array_keys($this->groupManager->displayNamesInGroup($group, $search, $limit, $offset));
			}
			$users = array_merge(...$users);
		}

		$usersDetails = [];
		foreach ($users as $userId) {
			$userId = (string) $userId;
			try {
				$userData = $this->getUserData($userId);
			} catch (OCSNotFoundException $e) {
				// We still want to return all other accounts, but this one was removed from the backends
				// yet they are still in our database. Might be a LDAP remnant.
				$userData = null;
				$this->logger->warning('Found one enabled account that is removed from its backend, but still exists in Nextcloud database', ['accountId' => $userId]);
			}
			// Do not insert empty entry
			if ($userData !== null) {
				$usersDetails[$userId] = $userData;
			} else {
				// Logged user does not have permissions to see this user
				// only showing its id
				$usersDetails[$userId] = ['id' => $userId];
			}
		}

		return new DataResponse([
			'users' => $usersDetails
		]);
	}

	/**
	 * Get the list of disabled users and their details
	 *
	 * @param string $search Text to search for
	 * @param ?int $limit Limit the amount of users returned
	 * @param int $offset Offset
	 * @return DataResponse<Http::STATUS_OK, array{users: array<string, Provisioning_APIUserDetails|array{id: string}>}, array{}>
	 *
	 * 200: Disabled users details returned
	 */
	#[NoAdminRequired]
	public function getDisabledUsersDetails(string $search = '', ?int $limit = null, int $offset = 0): DataResponse
	{
		$currentUser = $this->userSession->getUser();
		if ($currentUser === null) {
			return new DataResponse(['users' => []]);
		}
		if ($limit !== null && $limit < 0) {
			throw new InvalidArgumentException("Invalid limit value: $limit");
		}
		if ($offset < 0) {
			throw new InvalidArgumentException("Invalid offset value: $offset");
		}

		$users = [];

		// Admin? Or SubAdmin?
		$uid = $currentUser->getUID();
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($uid);
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($uid);
		if ($isAdmin || $isDelegatedAdmin) {
			$users = $this->userManager->getDisabledUsers($limit, $offset, $search);
			$users = array_map(fn(IUser $user): string => $user->getUID(), $users);
		} elseif ($subAdminManager->isSubAdmin($currentUser)) {
			$subAdminOfGroups = $subAdminManager->getSubAdminsGroups($currentUser);

			$users = [];
			/* We have to handle offset ourselve for correctness */
			$tempLimit = ($limit === null ? null : $limit + $offset);
			foreach ($subAdminOfGroups as $group) {
				$users = array_unique(array_merge(
					$users,
					array_map(
						fn(IUser $user): string => $user->getUID(),
						array_filter(
							$group->searchUsers($search),
							fn(IUser $user): bool => !$user->isEnabled()
						)
					)
				));
				if (($tempLimit !== null) && (count($users) >= $tempLimit)) {
					break;
				}
			}
			$users = array_slice($users, $offset, $limit);
		}

		$usersDetails = [];
		foreach ($users as $userId) {
			try {
				$userData = $this->getUserData($userId);
			} catch (OCSNotFoundException $e) {
				// We still want to return all other accounts, but this one was removed from the backends
				// yet they are still in our database. Might be a LDAP remnant.
				$userData = null;
				$this->logger->warning('Found one disabled account that was removed from its backend, but still exists in Nextcloud database', ['accountId' => $userId]);
			}
			// Do not insert empty entry
			if ($userData !== null) {
				$usersDetails[$userId] = $userData;
			} else {
				// Currently logged in user does not have permissions to see this user
				// only showing its id
				$usersDetails[$userId] = ['id' => $userId];
			}
		}

		return new DataResponse([
			'users' => $usersDetails
		]);
	}

	/**
	 * Gets the list of users sorted by lastLogin, from most recent to least recent
	 *
	 * @param string $search Text to search for
	 * @param ?int $limit Limit the amount of users returned
	 * @param int $offset Offset
	 * @return DataResponse<Http::STATUS_OK, array{users: array<string, Provisioning_APIUserDetails|array{id: string}>}, array{}>
	 *
	 * 200: Users details returned based on last logged in information
	 */
	#[AuthorizedAdminSetting(settings: Users::class)]
	public function getLastLoggedInUsers(
		string $search = '',
		?int $limit = null,
		int $offset = 0,
	): DataResponse {
		$currentUser = $this->userSession->getUser();
		if ($currentUser === null) {
			return new DataResponse(['users' => []]);
		}
		if ($limit !== null && $limit < 0) {
			throw new InvalidArgumentException("Invalid limit value: $limit");
		}
		if ($offset < 0) {
			throw new InvalidArgumentException("Invalid offset value: $offset");
		}

		$users = [];

		// For Admin alone user sorting based on lastLogin. For sub admin and groups this is not supported
		$users = $this->userManager->getLastLoggedInUsers($limit, $offset, $search);

		$usersDetails = [];
		foreach ($users as $userId) {
			try {
				$userData = $this->getUserData($userId);
			} catch (OCSNotFoundException $e) {
				// We still want to return all other accounts, but this one was removed from the backends
				// yet they are still in our database. Might be a LDAP remnant.
				$userData = null;
				$this->logger->warning('Found one account that was removed from its backend, but still exists in Nextcloud database', ['accountId' => $userId]);
			}
			// Do not insert empty entry
			if ($userData !== null) {
				$usersDetails[$userId] = $userData;
			} else {
				// Currently logged-in user does not have permissions to see this user
				// only showing its id
				$usersDetails[$userId] = ['id' => $userId];
			}
		}

		return new DataResponse([
			'users' => $usersDetails
		]);
	}



	/**
	 * @NoSubAdminRequired
	 *
	 * Search users by their phone numbers
	 *
	 * @param string $location Location of the phone number (for country code)
	 * @param array<string, string[]> $search Phone numbers to search for
	 * @return DataResponse<Http::STATUS_OK, array<string, string>, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, array<empty>, array{}>
	 *
	 * 200: Users returned
	 * 400: Invalid location
	 */
	#[NoAdminRequired]
	public function searchByPhoneNumbers(string $location, array $search): DataResponse
	{
		if ($this->phoneNumberUtil->getCountryCodeForRegion($location) === null) {
			// Not a valid region code
			return new DataResponse([], Http::STATUS_BAD_REQUEST);
		}

		/** @var IUser $user */
		$user = $this->userSession->getUser();
		$knownTo = $user->getUID();
		$defaultPhoneRegion = $this->config->getSystemValueString('default_phone_region');

		$normalizedNumberToKey = [];
		foreach ($search as $key => $phoneNumbers) {
			foreach ($phoneNumbers as $phone) {
				$normalizedNumber = $this->phoneNumberUtil->convertToStandardFormat($phone, $location);
				if ($normalizedNumber !== null) {
					$normalizedNumberToKey[$normalizedNumber] = (string) $key;
				}

				if ($defaultPhoneRegion !== '' && $defaultPhoneRegion !== $location && str_starts_with($phone, '0')) {
					// If the number has a leading zero (no country code),
					// we also check the default phone region of the instance,
					// when it's different to the user's given region.
					$normalizedNumber = $this->phoneNumberUtil->convertToStandardFormat($phone, $defaultPhoneRegion);
					if ($normalizedNumber !== null) {
						$normalizedNumberToKey[$normalizedNumber] = (string) $key;
					}
				}
			}
		}

		$phoneNumbers = array_keys($normalizedNumberToKey);

		if (empty($phoneNumbers)) {
			return new DataResponse();
		}

		// Cleanup all previous entries and only allow new matches
		$this->knownUserService->deleteKnownTo($knownTo);

		$userMatches = $this->accountManager->searchUsers(IAccountManager::PROPERTY_PHONE, $phoneNumbers);

		if (empty($userMatches)) {
			return new DataResponse();
		}

		$cloudUrl = rtrim($this->urlGenerator->getAbsoluteURL('/'), '/');
		if (strpos($cloudUrl, 'http://') === 0) {
			$cloudUrl = substr($cloudUrl, strlen('http://'));
		} elseif (strpos($cloudUrl, 'https://') === 0) {
			$cloudUrl = substr($cloudUrl, strlen('https://'));
		}

		$matches = [];
		foreach ($userMatches as $phone => $userId) {
			// Not using the ICloudIdManager as that would run a search for each contact to find the display name in the address book
			$matches[$normalizedNumberToKey[$phone]] = $userId . '@' . $cloudUrl;
			$this->knownUserService->storeIsKnownToUser($knownTo, $userId);
		}

		return new DataResponse($matches);
	}

	/**
	 * @throws Exception
	 */
	private function createNewUserId(): string
	{
		$attempts = 0;
		do {
			$uidCandidate = $this->secureRandom->generate(10, ISecureRandom::CHAR_HUMAN_READABLE);
			if (!$this->userManager->userExists($uidCandidate)) {
				return $uidCandidate;
			}
			$attempts++;
		} while ($attempts < 10);
		throw new Exception('Could not create non-existing user ID');
	}

	

	public function addUser(
		string $userid,
		string $password = null,
		string $displayName = null,
		string $email = '',
		array $groups = [],
		array $subadmin = [],
		string $quota = '524288000',
		string $language = '',
		?string $manager = null,
	) {
		try {
            
			// $user = $this->userSession->getUser();
           
			//  $isAdmin = $this->groupManager->isAdmin($userid);
			//  $isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($userid);
			 $subAdminManager = $this->groupManager->getSubAdmin();
        
			// if (empty($userid) && $this->config->getAppValue('core', 'newUser.generateUserID', 'no') === 'yes') {
			// 	$userid = $this->createNewUserId();
			// }
          
			if ($this->userManager->userExists($userid)) {
               
				throw new Exception('User already exists');
			}
  
   
			if ($groups !== []) {
				foreach ($groups as $group) {
                  
					if (!$this->groupManager->groupExists($group)) {
                       
						$this->groupManager->createGroup($group);
					}
					// if (!$isAdmin && !($isDelegatedAdmin && $group !== 'admin') && !$subAdminManager->isSubAdminOfGroup($user, $this->groupManager->get($group))) {
					// 	throw new Exception('Insufficient privileges for group %1$s');
					// }
				}
			} else {
				// if (!$isAdmin && !$isDelegatedAdmin) {
				// 	throw new Exception('No group specified (required for sub-admins)', 106);
				// }
			}
       

            
			$subadminGroups = [];

			if ($subadmin !== []) {
				foreach ($subadmin as $groupid) {
					$group = $this->groupManager->get($groupid);

					// Check if group exists
					if ($group === null) {
						throw new Exception('Sub-admin group does not exist');
					}
					// Check if trying to make subadmin of admin group

					if ($group->getGID() === 'admin') {
						throw new Exception('Cannot create sub-admins for admin group');
					}
					// Check if has permission to promote subadmins
					// if (!$subAdminManager->isSubAdminOfGroup($user, $group) && !$isAdmin && !$isDelegatedAdmin) {
					// 	throw new Exception('No permissions to promote sub-admins');
					// }
					$subadminGroups[] = $group;
				}
			}

        
			// xu ly them user

			$password = $password ?? "Edusoft@123_$userid";

			$newUser = $this->userManager->createUser($userid, $password);

		

			foreach ($groups as $group) {
				$this->groupManager->get($group)->addUser($newUser);
				
			}

			foreach ($subadminGroups as $group) {
				$subAdminManager->createSubAdmin($newUser, $group);
			}

			if ($displayName !== '') {
				try {
					$this->editUser($userid, self::USER_FIELD_DISPLAYNAME, $displayName);
				} catch (Exception $e) {
					if ($newUser instanceof IUser) {
						$newUser->delete();
					}
					throw $e;
				}
			}
            

			if ($quota !== '') {
				$this->editUser($userid, self::USER_FIELD_QUOTA, $quota);
			}

			if ($language !== '') {
				$this->editUser($userid, self::USER_FIELD_LANGUAGE, $language);
			}

			/**
			 * null -> nothing sent
			 * '' -> unset manager
			 * else -> set manager
			 */

			if ($manager !== null) {
				$this->editUser($userid, self::USER_FIELD_MANAGER, $manager);
			}
           

		

			return [
                'status'=>'success',
                'data' => "$userid is created" 
            ];
		} catch (Exception $e) {
            return [
                'status'=>'error',
                'message' => $e->getMessage()];
			
		}
	}

	/**
	 * @NoSubAdminRequired
	 *
	 * Get the details of a user
	 *
	 * @param string $userId ID of the user
	 * @return DataResponse<Http::STATUS_OK, Provisioning_APIUserDetails, array{}>
	 * @throws Exception
	 *
	 * 200: User returned
	 */
	
	public function getUser(string $userId): DataResponse
	{
		$includeScopes = false;
		$currentUser = $this->userSession->getUser();
		if ($currentUser && $currentUser->getUID() === $userId) {
			$includeScopes = true;
		}

		$data = $this->getUserData($userId, $includeScopes);
		// getUserData returns null if not enough permissions
		if ($data === null) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}
		return new DataResponse($data);
	}

	/**
	 * @NoSubAdminRequired
	 *
	 * Get the details of the current user
	 *
	 * @return DataResponse<Http::STATUS_OK, Provisioning_APIUserDetails, array{}>
	 * @throws Exception
	 *
	 * 200: Current user returned
	 */

	public function getCurrentUser(): DataResponse
	{
		$user = $this->userSession->getUser();
		if ($user) {
			/** @var Provisioning_APIUserDetails $data */
			$data = $this->getUserData($user->getUID(), true);
			return new DataResponse($data);
		}

		throw new Exception('', OCSController::RESPOND_UNAUTHORISED);
	}

	/**
	 * @NoSubAdminRequired
	 *
	 * Get a list of fields that are editable for the current user
	 *
	 * @return DataResponse<Http::STATUS_OK, string[], array{}>
	 * @throws Exception
	 *
	 * 200: Editable fields returned
	 */
	#[NoAdminRequired]
	public function getEditableFields(): DataResponse
	{
		$currentLoggedInUser = $this->userSession->getUser();
		if (!$currentLoggedInUser instanceof IUser) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		return $this->getEditableFieldsForUser($currentLoggedInUser->getUID());
	}

	/**
	 * @NoSubAdminRequired
	 *
	 * Get a list of fields that are editable for a user
	 *
	 * @param string $userId ID of the user
	 * @return DataResponse<Http::STATUS_OK, string[], array{}>
	 * @throws Exception
	 *
	 * 200: Editable fields for user returned
	 */
	#[NoAdminRequired]
	public function getEditableFieldsForUser(string $userId): DataResponse
	{
		$currentLoggedInUser = $this->userSession->getUser();
		if (!$currentLoggedInUser instanceof IUser) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		$permittedFields = [];

		if ($userId !== $currentLoggedInUser->getUID()) {
			$targetUser = $this->userManager->get($userId);
			if (!$targetUser instanceof IUser) {
				throw new Exception('', OCSController::RESPOND_NOT_FOUND);
			}

			$subAdminManager = $this->groupManager->getSubAdmin();
			$isAdmin = $this->groupManager->isAdmin($currentLoggedInUser->getUID());
			$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($currentLoggedInUser->getUID());
			if (
				!($isAdmin || $isDelegatedAdmin)
				&& !$subAdminManager->isUserAccessible($currentLoggedInUser, $targetUser)
			) {
				throw new Exception('', OCSController::RESPOND_NOT_FOUND);
			}
		} else {
			$targetUser = $currentLoggedInUser;
		}

		// Editing self (display, email)
		if ($this->config->getSystemValue('allow_user_to_change_display_name', true) !== false) {
			if (
				$targetUser->getBackend() instanceof ISetDisplayNameBackend
				|| $targetUser->getBackend()->implementsActions(Backend::SET_DISPLAYNAME)
			) {
				$permittedFields[] = IAccountManager::PROPERTY_DISPLAYNAME;
			}
			$permittedFields[] = IAccountManager::PROPERTY_EMAIL;
		}

		$permittedFields[] = IAccountManager::COLLECTION_EMAIL;
		$permittedFields[] = IAccountManager::PROPERTY_PHONE;
		$permittedFields[] = IAccountManager::PROPERTY_ADDRESS;
		$permittedFields[] = IAccountManager::PROPERTY_WEBSITE;
		$permittedFields[] = IAccountManager::PROPERTY_TWITTER;
		$permittedFields[] = IAccountManager::PROPERTY_FEDIVERSE;
		$permittedFields[] = IAccountManager::PROPERTY_ORGANISATION;
		$permittedFields[] = IAccountManager::PROPERTY_ROLE;
		$permittedFields[] = IAccountManager::PROPERTY_HEADLINE;
		$permittedFields[] = IAccountManager::PROPERTY_BIOGRAPHY;
		$permittedFields[] = IAccountManager::PROPERTY_PROFILE_ENABLED;

		return new DataResponse($permittedFields);
	}

	/**
	 * @NoSubAdminRequired
	 *
	 * Update multiple values of the user's details
	 *
	 * @param string $userId ID of the user
	 * @param string $collectionName Collection to update
	 * @param string $key Key that will be updated
	 * @param string $value New value for the key
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User values edited successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	#[UserRateLimit(limit: 5, period: 60)]
	public function editUserMultiValue(
		string $userId,
		string $collectionName,
		string $key,
		string $value
	): DataResponse {
		$currentLoggedInUser = $this->userSession->getUser();
		if ($currentLoggedInUser === null) {
			throw new Exception('', OCSController::RESPOND_UNAUTHORISED);
		}

		$targetUser = $this->userManager->get($userId);
		if ($targetUser === null) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		$subAdminManager = $this->groupManager->getSubAdmin();
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($currentLoggedInUser->getUID());
		$isAdminOrSubadmin = $this->groupManager->isAdmin($currentLoggedInUser->getUID())
			|| $subAdminManager->isUserAccessible($currentLoggedInUser, $targetUser);

		$permittedFields = [];
		if ($targetUser->getUID() === $currentLoggedInUser->getUID()) {
			// Editing self (display, email)
			$permittedFields[] = IAccountManager::COLLECTION_EMAIL;
			$permittedFields[] = IAccountManager::COLLECTION_EMAIL . self::SCOPE_SUFFIX;
		} else {
			// Check if admin / subadmin
			if ($isAdminOrSubadmin || $isDelegatedAdmin && !$this->groupManager->isInGroup($targetUser->getUID(), 'admin')) {
				// They have permissions over the user
				$permittedFields[] = IAccountManager::COLLECTION_EMAIL;
			} else {
				// No rights
				throw new Exception('', OCSController::RESPOND_NOT_FOUND);
			}
		}

		// Check if permitted to edit this field
		if (!in_array($collectionName, $permittedFields)) {
			throw new Exception('', 103);
		}

		switch ($collectionName) {
			case IAccountManager::COLLECTION_EMAIL:
				$userAccount = $this->accountManager->getAccount($targetUser);
				$mailCollection = $userAccount->getPropertyCollection(IAccountManager::COLLECTION_EMAIL);
				$mailCollection->removePropertyByValue($key);
				if ($value !== '') {
					$mailCollection->addPropertyWithDefaults($value);
					$property = $mailCollection->getPropertyByValue($key);
					if ($isAdminOrSubadmin && $property) {
						// admin set mails are auto-verified
						$property->setLocallyVerified(IAccountManager::VERIFIED);
					}
				}
				$this->accountManager->updateAccount($userAccount);
				if ($value === '' && $key === $targetUser->getPrimaryEMailAddress()) {
					$targetUser->setPrimaryEMailAddress('');
				}
				break;

			case IAccountManager::COLLECTION_EMAIL . self::SCOPE_SUFFIX:
				$userAccount = $this->accountManager->getAccount($targetUser);
				$mailCollection = $userAccount->getPropertyCollection(IAccountManager::COLLECTION_EMAIL);
				$targetProperty = null;
				foreach ($mailCollection->getProperties() as $property) {
					if ($property->getValue() === $key) {
						$targetProperty = $property;
						break;
					}
				}
				if ($targetProperty instanceof IAccountProperty) {
					try {
						$targetProperty->setScope($value);
						$this->accountManager->updateAccount($userAccount);
					} catch (InvalidArgumentException $e) {
						throw new Exception('');
					}
				} else {
					throw new Exception('');
				}
				break;

			default:
				throw new Exception('', 103);
		}
		return new DataResponse();
	}

	/**
	 * @NoSubAdminRequired
	 *
	 * Update a value of the user's details
	 *
	 * @param string $userId ID of the user
	 * @param string $key Key that will be updated
	 * @param string $value New value for the key
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User value edited successfully
	 */
	public function editUser(string $userId, string $key, string $value): DataResponse
	{
		$currentLoggedInUser = $this->userSession->getUser();

		$targetUser = $this->userManager->get($userId);
      
		if ($targetUser === null) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		
		// Process the edit
		switch ($key) {
			case self::USER_FIELD_DISPLAYNAME:
			case IAccountManager::PROPERTY_DISPLAYNAME:
				try {
					$targetUser->setDisplayName($value);
				} catch (InvalidArgumentException $e) {
					throw new Exception($e->getMessage());
				}
				break;
			case self::USER_FIELD_QUOTA:
				$quota = $value;
				if ($quota !== 'none' && $quota !== 'default') {
					if (is_numeric($quota)) {
						$quota = (float) $quota;
					} else {
						$quota = \OCP\Util::computerFileSize($quota);
					}
					if ($quota === false) {
						throw new Exception('Invalid quota value: %1$s');
					}
					if ($quota === -1) {
						$quota = 'none';
					} else {
						$maxQuota = (int) $this->config->getAppValue('files', 'max_quota', '-1');
						if ($maxQuota !== -1 && $quota > $maxQuota) {
							throw new Exception('Invalid quota value. %1$s is exceeding the maximum quota');
						}
						$quota = \OCP\Util::humanFileSize($quota);
					}
				}
				// no else block because quota can be set to 'none' in previous if
				if ($quota === 'none') {
					$allowUnlimitedQuota = $this->config->getAppValue('files', 'allow_unlimited_quota', '1') === '1';
					if (!$allowUnlimitedQuota) {
						throw new Exception('Unlimited quota is forbidden on this instance');
					}
				}
				$targetUser->setQuota($quota);
				break;
			case self::USER_FIELD_MANAGER:
				$targetUser->setManagerUids([$value]);
				break;
			case self::USER_FIELD_PASSWORD:
				try {
					if (strlen($value) > IUserManager::MAX_PASSWORD_LENGTH) {
						throw new Exception('Invalid password value');
					}
					if (!$targetUser->canChangePassword()) {
						throw new Exception('Setting the password is not supported by the users backend');
					}
					$targetUser->setPassword($value);
				} catch (HintException $e) { // password policy error
					throw new Exception($e->getMessage(), 107);
				}
				break;
			case self::USER_FIELD_LANGUAGE:
				$languagesCodes = $this->l10nFactory->findAvailableLanguages();
				if (!in_array($value, $languagesCodes, true) && $value !== 'en') {
					throw new Exception('Invalid language');
				}
				$this->config->setUserValue($targetUser->getUID(), 'core', 'lang', $value);
				break;
			case self::USER_FIELD_LOCALE:
				if (!$this->l10nFactory->localeExists($value)) {
					throw new Exception('Invalid locale');
				}
				$this->config->setUserValue($targetUser->getUID(), 'core', 'locale', $value);
				break;
			case self::USER_FIELD_FIRST_DAY_OF_WEEK:
				$intValue = (int)$value;
				if ($intValue < -1 || $intValue > 6) {
					throw new Exception('Invalid first day of week');
				}
				if ($intValue === -1) {
					$this->config->deleteUserValue($targetUser->getUID(), 'core', AUserData::USER_FIELD_FIRST_DAY_OF_WEEK);
				} else {
					$this->config->setUserValue($targetUser->getUID(), 'core', AUserData::USER_FIELD_FIRST_DAY_OF_WEEK, $value);
				}
				break;
			case self::USER_FIELD_NOTIFICATION_EMAIL:
				$success = false;
				if ($value === '' || filter_var($value, FILTER_VALIDATE_EMAIL)) {
					try {
						$targetUser->setPrimaryEMailAddress($value);
						$success = true;
					} catch (InvalidArgumentException $e) {
						$this->logger->info(
							'Cannot set primary email, because provided address is not verified',
							[
								'app' => 'provisioning_api',
								'exception' => $e,
							]
						);
					}
				}
				if (!$success) {
					throw new Exception('error');
				}
				break;
			case IAccountManager::PROPERTY_EMAIL:
				if (filter_var($value, FILTER_VALIDATE_EMAIL) || $value === '') {
					$targetUser->setEMailAddress($value);
				} else {
					throw new Exception('error');
				}
				break;
			case IAccountManager::COLLECTION_EMAIL:
				if (filter_var($value, FILTER_VALIDATE_EMAIL) && $value !== $targetUser->getSystemEMailAddress()) {
					$userAccount = $this->accountManager->getAccount($targetUser);
					$mailCollection = $userAccount->getPropertyCollection(IAccountManager::COLLECTION_EMAIL);

					if ($mailCollection->getPropertyByValue($value)) {
						throw new Exception('error');
					}

					$mailCollection->addPropertyWithDefaults($value);
					$this->accountManager->updateAccount($userAccount);
				} else {
					throw new Exception('error');
				}
				break;
			case IAccountManager::PROPERTY_PHONE:
			case IAccountManager::PROPERTY_ADDRESS:
			case IAccountManager::PROPERTY_WEBSITE:
			case IAccountManager::PROPERTY_TWITTER:
			case IAccountManager::PROPERTY_FEDIVERSE:
			case IAccountManager::PROPERTY_ORGANISATION:
			case IAccountManager::PROPERTY_ROLE:
			case IAccountManager::PROPERTY_HEADLINE:
			case IAccountManager::PROPERTY_BIOGRAPHY:
			case IAccountManager::PROPERTY_BIRTHDATE:
				$userAccount = $this->accountManager->getAccount($targetUser);
				try {
					$userProperty = $userAccount->getProperty($key);
					if ($userProperty->getValue() !== $value) {
						try {
							$userProperty->setValue($value);
							if ($userProperty->getName() === IAccountManager::PROPERTY_PHONE) {
								$this->knownUserService->deleteByContactUserId($targetUser->getUID());
							}
						} catch (InvalidArgumentException $e) {
							throw new Exception('Invalid ' . $e->getMessage());
						}
					}
				} catch (PropertyDoesNotExistException $e) {
					$userAccount->setProperty($key, $value, IAccountManager::SCOPE_PRIVATE, IAccountManager::NOT_VERIFIED);
				}
				try {
					$this->accountManager->updateAccount($userAccount);
				} catch (InvalidArgumentException $e) {
					throw new Exception('Invalid ' . $e->getMessage());
				}
				break;
			case IAccountManager::PROPERTY_PROFILE_ENABLED:
				$userAccount = $this->accountManager->getAccount($targetUser);
				try {
					$userProperty = $userAccount->getProperty($key);
					if ($userProperty->getValue() !== $value) {
						$userProperty->setValue($value);
					}
				} catch (PropertyDoesNotExistException $e) {
					$userAccount->setProperty($key, $value, IAccountManager::SCOPE_LOCAL, IAccountManager::NOT_VERIFIED);
				}
				$this->accountManager->updateAccount($userAccount);
				break;
			case IAccountManager::PROPERTY_DISPLAYNAME . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_EMAIL . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_PHONE . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_ADDRESS . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_WEBSITE . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_TWITTER . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_FEDIVERSE . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_ORGANISATION . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_ROLE . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_HEADLINE . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_BIOGRAPHY . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_PROFILE_ENABLED . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_BIRTHDATE . self::SCOPE_SUFFIX:
			case IAccountManager::PROPERTY_AVATAR . self::SCOPE_SUFFIX:
				$propertyName = substr($key, 0, strlen($key) - strlen(self::SCOPE_SUFFIX));
				$userAccount = $this->accountManager->getAccount($targetUser);
				$userProperty = $userAccount->getProperty($propertyName);
				if ($userProperty->getScope() !== $value) {
					try {
						$userProperty->setScope($value);
						$this->accountManager->updateAccount($userAccount);
					} catch (InvalidArgumentException $e) {
						throw new Exception('Invalid ' . $e->getMessage());
					}
				}
				break;
			default:
				throw new Exception('', 113);
		}
		return new DataResponse();
	}

	/**
	 * Wipe all devices of a user
	 *
	 * @param string $userId ID of the user
	 *
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 *
	 * @throws Exception
	 *
	 * 200: Wiped all user devices successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	public function wipeUserDevices(string $userId): DataResponse
	{
		/** @var IUser $currentLoggedInUser */
		$currentLoggedInUser = $this->userSession->getUser();

		$targetUser = $this->userManager->get($userId);

		if ($targetUser === null) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		if ($targetUser->getUID() === $currentLoggedInUser->getUID()) {
			throw new Exception('error');
		}

		// If not permitted
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($currentLoggedInUser->getUID());
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($currentLoggedInUser->getUID());
		if (!$isAdmin && !($isDelegatedAdmin && !$this->groupManager->isInGroup($targetUser->getUID(), 'admin')) && !$subAdminManager->isUserAccessible($currentLoggedInUser, $targetUser)) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		$this->remoteWipe->markAllTokensForWipe($targetUser);

		return new DataResponse();
	}

	/**
	 * Delete a user
	 *
	 * @param string $userId ID of the user
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User deleted successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	public function deleteUser(string $userId): DataResponse
	{
		$currentLoggedInUser = $this->userSession->getUser();

		$targetUser = $this->userManager->get($userId);

		if ($targetUser === null) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		if ($targetUser->getUID() === $currentLoggedInUser->getUID()) {
			throw new Exception('error');
		}

		// If not permitted
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($currentLoggedInUser->getUID());
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($currentLoggedInUser->getUID());
		if (!$isAdmin && !($isDelegatedAdmin && !$this->groupManager->isInGroup($targetUser->getUID(), 'admin')) && !$subAdminManager->isUserAccessible($currentLoggedInUser, $targetUser)) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		// Go ahead with the delete
		if ($targetUser->delete()) {
			return new DataResponse();
		} else {
			throw new Exception('error');
		}
	}

	/**
	 * Disable a user
	 *
	 * @param string $userId ID of the user
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User disabled successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	public function disableUser(string $userId): DataResponse
	{
		return $this->setEnabled($userId, false);
	}

	/**
	 * Enable a user
	 *
	 * @param string $userId ID of the user
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User enabled successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	public function enableUser(string $userId): DataResponse
	{
		return $this->setEnabled($userId, true);
	}

	/**
	 * @param string $userId
	 * @param bool $value
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 */
	private function setEnabled(string $userId, bool $value): DataResponse
	{
		$currentLoggedInUser = $this->userSession->getUser();

		$targetUser = $this->userManager->get($userId);
		if ($targetUser === null || $targetUser->getUID() === $currentLoggedInUser->getUID()) {
			throw new Exception('error');
		}

		// If not permitted
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($currentLoggedInUser->getUID());
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($currentLoggedInUser->getUID());
		if (!$isAdmin && !($isDelegatedAdmin && !$this->groupManager->isInGroup($targetUser->getUID(), 'admin')) && !$subAdminManager->isUserAccessible($currentLoggedInUser, $targetUser)) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		// enable/disable the user now
		$targetUser->setEnabled($value);
		return new DataResponse();
	}

	/**
	 * @NoSubAdminRequired
	 *
	 * Get a list of groups the user belongs to
	 *
	 * @param string $userId ID of the user
	 * @return DataResponse<Http::STATUS_OK, array{groups: string[]}, array{}>
	 * @throws Exception
	 *
	 * 200: Users groups returned
	 */
	#[NoAdminRequired]
	public function getUsersGroups(string $userId): DataResponse
	{
		$loggedInUser = $this->userSession->getUser();

		$targetUser = $this->userManager->get($userId);
		if ($targetUser === null) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		$isAdmin = $this->groupManager->isAdmin($loggedInUser->getUID());
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($loggedInUser->getUID());
		if ($targetUser->getUID() === $loggedInUser->getUID() || $isAdmin || $isDelegatedAdmin) {
			// Self lookup or admin lookup
			return new DataResponse([
				'groups' => $this->groupManager->getUserGroupIds($targetUser)
			]);
		} else {
			$subAdminManager = $this->groupManager->getSubAdmin();

			// Looking up someone else
			if ($subAdminManager->isUserAccessible($loggedInUser, $targetUser)) {
				// Return the group that the method caller is subadmin of for the user in question
				/** @var IGroup[] $getSubAdminsGroups */
				$getSubAdminsGroups = $subAdminManager->getSubAdminsGroups($loggedInUser);
				foreach ($getSubAdminsGroups as $key => $group) {
					$getSubAdminsGroups[$key] = $group->getGID();
				}
				/** @var string[] $groups */
				$groups = array_intersect(
					$getSubAdminsGroups,
					$this->groupManager->getUserGroupIds($targetUser)
				);
				return new DataResponse(['groups' => $groups]);
			} else {
				// Not permitted
				throw new Exception('', OCSController::RESPOND_NOT_FOUND);
			}
		}
	}

	/**
	 * Add a user to a group
	 *
	 * @param string $userId ID of the user
	 * @param string $groupid ID of the group
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User added to group successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	public function addToGroup(string $userId, string $groupid = ''): DataResponse
	{
		if ($groupid === '') {
			throw new Exception('error');
		}

		$group = $this->groupManager->get($groupid);
		$targetUser = $this->userManager->get($userId);
		if ($group === null) {
			throw new Exception('');
		}
		if ($targetUser === null) {
			throw new Exception('', 103);
		}

		// If they're not an admin, check they are a subadmin of the group in question
		$loggedInUser = $this->userSession->getUser();
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($loggedInUser->getUID());
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($loggedInUser->getUID());
		if (!$isAdmin && !($isDelegatedAdmin && $groupid !== 'admin') && !$subAdminManager->isSubAdminOfGroup($loggedInUser, $group)) {
			throw new Exception('', 104);
		}

		// Add user to group
		$group->addUser($targetUser);
		return new DataResponse();
	}

	/**
	 * Remove a user from a group
	 *
	 * @param string $userId ID of the user
	 * @param string $groupid ID of the group
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User removed from group successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	public function removeFromGroup(string $userId, string $groupid): DataResponse
	{
		$loggedInUser = $this->userSession->getUser();

		if ($groupid === null || trim($groupid) === '') {
			throw new Exception('error');
		}

		$group = $this->groupManager->get($groupid);
		if ($group === null) {
			throw new Exception('');
		}

		$targetUser = $this->userManager->get($userId);
		if ($targetUser === null) {
			throw new Exception('', 103);
		}

		// If they're not an admin, check they are a subadmin of the group in question
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($loggedInUser->getUID());
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($loggedInUser->getUID());
		if (!$isAdmin && !($isDelegatedAdmin && $groupid !== 'admin') && !$subAdminManager->isSubAdminOfGroup($loggedInUser, $group)) {
			throw new Exception('', 104);
		}

		// Check they aren't removing themselves from 'admin' or their 'subadmin; group
		if ($targetUser->getUID() === $loggedInUser->getUID()) {
			if ($isAdmin || $isDelegatedAdmin) {
				if ($group->getGID() === 'admin') {
					throw new Exception('Cannot remove yourself from the admin group');
				}
			} else {
				// Not an admin, so the user must be a subadmin of this group, but that is not allowed.
				throw new Exception('Cannot remove yourself from this group as you are a sub-admin');
			}
		} elseif (!($isAdmin || $isDelegatedAdmin)) {
			/** @var IGroup[] $subAdminGroups */
			$subAdminGroups = $subAdminManager->getSubAdminsGroups($loggedInUser);
			$subAdminGroups = array_map(function (IGroup $subAdminGroup) {
				return $subAdminGroup->getGID();
			}, $subAdminGroups);
			$userGroups = $this->groupManager->getUserGroupIds($targetUser);
			$userSubAdminGroups = array_intersect($subAdminGroups, $userGroups);

			if (count($userSubAdminGroups) <= 1) {
				// Subadmin must not be able to remove a user from all their subadmin groups.
				throw new Exception('Not viable to remove user from the last group you are sub-admin of');
			}
		}

		// Remove user from group
		$group->removeUser($targetUser);
		return new DataResponse();
	}

	/**
	 * Make a user a subadmin of a group
	 *
	 * @param string $userId ID of the user
	 * @param string $groupid ID of the group
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User added as group subadmin successfully
	 */
	#[AuthorizedAdminSetting(settings: Users::class)]
	#[PasswordConfirmationRequired]
	public function addSubAdmin(string $userId, string $groupid): DataResponse
	{
		$group = $this->groupManager->get($groupid);
		$user = $this->userManager->get($userId);

		// Check if the user exists
		if ($user === null) {
			throw new Exception('User does not exist');
		}
		// Check if group exists
		if ($group === null) {
			throw new Exception('Group does not exist');
		}
		// Check if trying to make subadmin of admin group
		if ($group->getGID() === 'admin') {
			throw new Exception('Cannot create sub-admins for admin group');
		}

		$subAdminManager = $this->groupManager->getSubAdmin();

		// We cannot be subadmin twice
		if ($subAdminManager->isSubAdminOfGroup($user, $group)) {
			return new DataResponse();
		}
		// Go
		$subAdminManager->createSubAdmin($user, $group);
		return new DataResponse();
	}

	/**
	 * Remove a user from the subadmins of a group
	 *
	 * @param string $userId ID of the user
	 * @param string $groupid ID of the group
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: User removed as group subadmin successfully
	 */
	#[AuthorizedAdminSetting(settings: Users::class)]
	#[PasswordConfirmationRequired]
	public function removeSubAdmin(string $userId, string $groupid): DataResponse
	{
		$group = $this->groupManager->get($groupid);
		$user = $this->userManager->get($userId);
		$subAdminManager = $this->groupManager->getSubAdmin();

		// Check if the user exists
		if ($user === null) {
			throw new Exception('User does not exist');
		}
		// Check if the group exists
		if ($group === null) {
			throw new Exception('Group does not exist');
		}
		// Check if they are a subadmin of this said group
		if (!$subAdminManager->isSubAdminOfGroup($user, $group)) {
			throw new Exception('User is not a sub-admin of this group');
		}

		// Go
		$subAdminManager->deleteSubAdmin($user, $group);
		return new DataResponse();
	}

	/**
	 * Get the groups a user is a subadmin of
	 *
	 * @param string $userId ID if the user
	 * @return DataResponse<Http::STATUS_OK, string[], array{}>
	 * @throws Exception
	 *
	 * 200: User subadmin groups returned
	 */
	#[AuthorizedAdminSetting(settings: Users::class)]
	public function getUserSubAdminGroups(string $userId): DataResponse
	{
		$groups = $this->getUserSubAdminGroupsData($userId);
		return new DataResponse($groups);
	}

	/**
	 * Resend the welcome message
	 *
	 * @param string $userId ID if the user
	 * @return DataResponse<Http::STATUS_OK, array<empty>, array{}>
	 * @throws Exception
	 *
	 * 200: Resent welcome message successfully
	 */
	#[PasswordConfirmationRequired]
	#[NoAdminRequired]
	public function resendWelcomeMessage(string $userId): DataResponse
	{
		$currentLoggedInUser = $this->userSession->getUser();

		$targetUser = $this->userManager->get($userId);
		if ($targetUser === null) {
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		// Check if admin / subadmin
		$subAdminManager = $this->groupManager->getSubAdmin();
		$isAdmin = $this->groupManager->isAdmin($currentLoggedInUser->getUID());
		$isDelegatedAdmin = $this->groupManager->isDelegatedAdmin($currentLoggedInUser->getUID());
		if (
			!$subAdminManager->isUserAccessible($currentLoggedInUser, $targetUser)
			&& !($isAdmin || $isDelegatedAdmin)
		) {
			// No rights
			throw new Exception('', OCSController::RESPOND_NOT_FOUND);
		}

		$email = $targetUser->getEMailAddress();
		if ($email === '' || $email === null) {
			throw new Exception('Email address not available');
		}

		try {
			if ($this->config->getUserValue($targetUser->getUID(), 'core', 'lostpassword')) {
				$emailTemplate = $this->newUserMailHelper->generateTemplate($targetUser, true);
			} else {
				$emailTemplate = $this->newUserMailHelper->generateTemplate($targetUser, false);
			}

			$this->newUserMailHelper->sendMail($targetUser, $emailTemplate);
		} catch (\Exception $e) {
			$this->logger->error(
				"Can't send new user mail to $email",
				[
					'app' => 'settings',
					'exception' => $e,
				]
			);
			throw new Exception('Sending email failed');
		}

		return new DataResponse();
	}
}
