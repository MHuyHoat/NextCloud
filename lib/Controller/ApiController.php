<?php

declare(strict_types=1);

namespace OCA\EduSoft\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
/**
 * @psalm-suppress UnusedClass
 */
class ApiController extends Controller {
	/**
	 * An example API endpoint
	 *
	 * @return DataResponse<Http::STATUS_OK, array{message: string}, array{}>
	 *
	 * 200: Data returned
	 */
	#[NoCSRFRequired]
	#[NoAdminRequired]
    #[PublicPage]
	 #[ApiRoute(verb: 'GET', url: '/api')]
	public function index(): DataResponse {
		return new DataResponse(
			['message' => 'Edusoft Api !']
		);
	}
}
