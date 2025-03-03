<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http');
$host = $protocol . '://' . $_SERVER['HTTP_HOST'];

header('X-Frame-Options: ALLOW-FROM *');
if (isset($_REQUEST['jwt'])) {
    $jwt = $_REQUEST['jwt'];
} else {
    die('JWT not found');
}


try {
    require_once __DIR__ . '/../vendor-bin/php-jwt/src/Key.php';
    require_once __DIR__ . '/../vendor-bin/php-jwt/src/JWT.php';



    $JWT_SECRET = "2ZmRAqyN47GyE1Fm6ElhorU4Ai4eg934maERKd8bUKqBVkdBfVKD8KqpcToexGf5";

    $decode_token = JWT::decode($jwt, new Key($JWT_SECRET, 'HS256'));
    $decode_arr = (array) $decode_token;

    $userName = $decode_arr['user_name'] ?? '';

    $password = 'Edusoft@123_' . $userName;
    if(isset($_REQUEST['reset'])){
        $url = "$host/ocs/v2.php/apps/edusoft/reset-password?userid=$userName&password=$password&jwt=$jwt";
     
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
    }

    $accessToken = '';
} catch (\Throwable $th) {
    die($th->getMessage());
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Choose File NextCloud</title>
    
    <script src="./node_modules/nextcloud-webdav-filepicker/js/filePickerWrapper.js"></script>
    <style>
        .modal-wrapper[data-v-09b21bad] {
            display: block
        }

        .picker__content[data-v-16f5465e] {
            width: 900px;
            background: var(--color-main-background);
            color: var(--color-main-text);
            display: flex;
            flex-direction: column;
            padding: 20px;
            font-size: var(--default-font-size);
            font-family: var(--font-face);
        }

        .modal-wrapper--large .modal-container[data-v-09b21bad] {
            max-width: 100%;
            width: 100%;
            height: 100%;

        }

        .picker__content[data-v-16f5465e] {
            width: 100%;
            background: var(--color-main-background);
            color: var(--color-main-text);
            display: flex;
            flex-direction: column;
            padding: 20px;
            font-size: var(--default-font-size);
            font-family: var(--font-face);
        }

        .modal-wrapper--large .modal-container[data-v-09b21bad] {
            max-width: 100%;
            width: 100%;
            max-height: 100%;
        }
    </style>
</head>

<body>

</body>

<script>
    function main() {
        // get url values
        const uri = window.location.search.substring(1)


        const initialUrl = "<?php echo $host; ?>"
        const initialLogin = "<?php echo $userName; ?>"
        const initialPassword = "<?php echo $password; ?>";
        const initialAccessToken = "<?php echo $accessToken; ?>"
        const initialColor = '#0082c9'
        const initialDarkMode = false;
        var filepicker = null


        filepicker = window.createFilePicker('mount_point', {
            url: initialUrl,
            login: initialLogin,
            password: initialPassword,
            accessToken: initialAccessToken,
            useCookies: false,
            themeColor: initialColor,
            darkMode: initialDarkMode,
            displayPreviews: true,
            displayQuotaRefresh: true,
            multipleDownload: true,
            multipleUpload: true,
            closeOnError: false,
            enableGetFilesPath: true,
            enableGetFilesLink: true,
            enableDownloadFiles: true,
            enableGetSaveFilePath: true,
            enableGetUploadFileLink: true,
            enableUploadFiles: true,
            useWebapppassword: true,
        })
         filepicker.updatePassword("<?php echo $password; ?>")

     
        document.addEventListener('filepicker-unauthorized', (e) => {
			console.log('file picker got an unauthorized response')
			
		})
        


        filepicker.getFilesLink({
            expirationDate: new Date('2050-01-01'),
            protectionPassword: 'example passwd',
            allowEdition: true,
            linkLabel: 'custom link label',
        })
        document.addEventListener('get-files-link', (e) => {
            window.parent.postMessage({
                type: 'file-selected',
                file: e.detail.shareLinks
            }, '*');


        })

    }
   
    document.addEventListener('DOMContentLoaded', (event) => {
        main()
    })
</script>

<style type="text/css">
    .button-vue[data-v-4c8c7bff]:focus-visible {
        outline: none !important;
    }

    .ribbon {
        background-color: #0082c9;
        overflow: hidden;
        white-space: nowrap;
        position: fixed;
        right: -70px;
        top: 75px;
        -webkit-transform: rotate(45deg);
        -moz-transform: rotate(45deg);
        -ms-transform: rotate(45deg);
        -o-transform: rotate(45deg);
        transform: rotate(45deg);
        -webkit-box-shadow: 0 0 10px #888;
        -moz-box-shadow: 0 0 10px #888;
        box-shadow: 0 0 10px #888;
    }

    .ribbon a {
        border: 1px solid #faa;
        color: #fff;
        display: block;
        font: bold 100% 'Helvetica Neue', Helvetica, Arial, sans-serif;
        margin: 1px 0;
        padding: 10px 50px;
        text-align: center;
        text-decoration: none;
        text-shadow: 0 0 5px #444;
    }
</style>