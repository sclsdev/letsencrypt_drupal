#!/usr/bin/env php
<?php

// This example requires `league/oauth2-client` package.
// Run `composer require league/oauth2-client` before running.
require __DIR__ . '/vendor/autoload.php';

use League\OAuth2\Client\Provider\GenericProvider;
use GuzzleHttp\Client;
use Commando\Command;
use GuzzleHttp\Exception\ClientException;


$cmd = new Commando\Command();

// Define script arguments

$cmd->option()
  ->require()
  ->referredToAs('Environment ID')
  ->describedAs('Environment ID. Can be found in the link to environment on application page.');

$cmd->option()
  ->require()
  ->describedAs('Private keyfile path')
  ->referredToAs('KEYFILE')
  ->expectsFile();

$cmd->option()
  ->require()
  ->describedAs('Full certificate chain path')
  ->referredToAs('FULLCHAINFILE')
  ->expectsFile();

$cmd->option()
  ->require()
  ->describedAs('Intermediate certificates path')
  ->referredToAs('CHAINFILE')
  ->expectsFile();

$cmd->option()
  ->require()
  ->referredToAs('Timestamp')
  ->describedAs('Timestamp of sitemap creation');

$cmd->option("a")
  ->aka('activate')
  ->describedAs('Activate the deployed certificate.')
  ->boolean();

$cmd->option("p")
  ->aka('label-prefix')
  ->describedAs('Optionally specify a label prefix. Defaults to \'cert\'');

$cmd->option()
  ->require()
  ->describedAs('Domain name')
  ->referredToAs('DOMAIN');

list($environment_id, $keyfile_path, $full_certificate_chain_path, $intermediate_certificates, $timestamp, $domain) = $cmd;

// Format timestamp as ISO 8601 date
$timestamp_formatted = gmdate('c', $timestamp);

$secrets = extract_secrets($cmd);

$base_url = 'https://cloud.acquia.com/api/';
// Create label beforehand, so it can be used at multiple places.
if ($label_prefix = $cmd['label-prefix']) {
    $label = "{$label_prefix}_{$timestamp_formatted}_{$domain}";
} else {
  $label = "cert_{$timestamp_formatted}";
}

// See https://docs.acquia.com/cloud-platform/develop/api/auth/
// for how to generate a client ID and Secret.
$clientId = $secrets['token'];
$clientSecret = $secrets['secret'];

$provider = new GenericProvider([
    'clientId'                => $clientId,
    'clientSecret'            => $clientSecret,
    'urlAuthorize'            => '',
    'urlAccessToken'          => 'https://accounts.acquia.com/api/auth/oauth/token',
    'urlResourceOwnerDetails' => '',
]);

try {

    $api_method = "environments/{$environment_id}/ssl/certificates";

    // Try to get an access token using the client credentials grant.
    $accessToken = $provider->getAccessToken('client_credentials');

    $body = json_encode([
        'legacy' => false,
        'certificate' => file_get_contents($full_certificate_chain_path),
        'private_key' => file_get_contents($keyfile_path),
        'ca_certificates' => file_get_contents($intermediate_certificates),
        'label' => $label,
    ]);

    // Generate a request object using the access token.
    $request = $provider->getAuthenticatedRequest(
        'POST',
        $base_url . $api_method,
        $accessToken,
        [
            'headers' => ['Content-Type' => 'application/json'],
            'body' => $body

        ]
    );

    // Send the request.
    $client = new Client();
    $response = $client->send($request);

    $responseBody = $response->getBody();

} catch (ClientException $e) {
    print $e->getMessage();
    print_response_message($e->getResponse(), $cmd);
}

print_response_message($response->getBody(), $cmd);

if ($response->getStatusCode() == 202 && $cmd['activate']) {
  // Get all  certificates
  $certificates = get_deployed_certificates($environment_id, $client, $base_url, $cmd, $provider, $accessToken);
  // Activate it
  // Loop through the certificates, get ID of the one which has the same Label as the current one
  if (is_array($certificates)) {
    foreach ($certificates as $cert_id => $cert_label) {
      // $label is the label of currently deployed certificate
      if ($label === $cert_label) {
        // Request.
        try {
          $api_method = "environments/{$environment_id}/ssl/certificates/{$cert_id}/actions/activate";
          $response = $client->send($provider->getAuthenticatedRequest('POST', $base_url . $api_method, $accessToken, []));
        } catch (ClientException $e) {
            print $e->getMessage();
            print_response_message($e->getResponse(), $cmd);
        }
        print_response_message($response->getBody(), $cmd);
      }
    }
  }
}

/**
 * Helper function, which extracts saved secrets from secrets.settings.php file.
 */
function extract_secrets($cmd) {
  // Load Acquia Cloud secrets file
  $secrets_file = sprintf('/mnt/files/%s.%s/secrets.settings.php', $_ENV['AH_SITE_GROUP'], $_ENV['AH_SITE_ENVIRONMENT']);

  if (!file_exists($secrets_file)) {
    $cmd->error(new Exception('The secrets file wasn\'t found. Please read https://docs.acquia.com/resource/secrets/ and create one.'));
  }

  require $secrets_file;

  if (!isset($acquia_cloud_token, $acquia_cloud_secret)) {
    $cmd->error(new Exception('The script needs variables $acquia_cloud_token and $acquia_cloud_secret defined in the secrets.settings.php file.'));
  }

  return [
    'token' => $acquia_cloud_token,
    'secret' => $acquia_cloud_secret,
  ];
}

/**
 * Helper function, returns array of deployed certificates, keyed by
 * certificate ID.
 *
 * @param $environment_id
 * @param $client
 * @param $base_url
 * @param $cmd
 *
 * @return array
 */
function get_deployed_certificates($environment_id, $client, $base_url, $cmd, $provider, $accessToken) {
  // Request.
  try {
    $api_method = "environments/{$environment_id}/ssl/certificates";
    $response = $client->send($provider->getAuthenticatedRequest('GET', $base_url . $api_method, $accessToken, []));
  } catch (ClientException $e) {
        $cmd->error($e->getMessage());
  }

  if ($deployed_certificates = json_decode($response->getBody(), TRUE)) {
    $certificates_map = [];
    foreach ($deployed_certificates['_embedded']['items'] as $item) {
      $certificates_map[$item['id']] = $item['label'];
    }
    return $certificates_map;
  }
}

/**
 * Prints response from Acquia Cloud API.
 *
 * @param $response_body
 * @param $cmd
 */
function print_response_message($response_body, $cmd) {
  // If it's a Response object, extract the body content
  if ($response_body instanceof \Psr\Http\Message\ResponseInterface) {
    $response_body = $response_body->getBody()->getContents();
  }

  $response_body = json_decode($response_body, TRUE);

  if (array_key_exists('error', $response_body)) {
    $message = is_array($response_body['message']) ? json_encode($response_body['message']) : $response_body['message'];
    $cmd->error(new Exception($message));
  }

  print $response_body['message'] . PHP_EOL;
}
