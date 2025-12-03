<?php

use Commando\Command;
use GuzzleHttp\Exception\ClientException;

/**
 * Extract saved secrets from secrets.settings.php file.
 */
function extract_secrets($cmd) {
  $secrets_file = sprintf(
    '/mnt/files/%s.%s/secrets.settings.php',
    $_ENV['AH_SITE_GROUP'],
    $_ENV['AH_SITE_ENVIRONMENT']
  );

  if (!file_exists($secrets_file)) {
    $cmd->error(new Exception(
      'The secrets file wasn\'t found. Please read https://docs.acquia.com/resource/secrets/ and create one.'
    ));
  }

  require $secrets_file;

  if (!isset($acquia_cloud_token, $acquia_cloud_secret)) {
    $cmd->error(new Exception(
      'The script needs variables $acquia_cloud_token and $acquia_cloud_secret defined in the secrets.settings.php file.'
    ));
  }

  return [
    'token' => $acquia_cloud_token,
    'secret' => $acquia_cloud_secret,
  ];
}

/**
 * Returns array of deployed certificates keyed by certificate ID.
 */
function get_deployed_certificates($environment_id, $client, $base_url, $cmd, $provider, $accessToken) {
  try {
    $api_method = "environments/{$environment_id}/ssl/certificates";
    $response = $client->send(
      $provider->getAuthenticatedRequest('GET', $base_url . $api_method, $accessToken, [])
    );
  } catch (ClientException $e) {
    $cmd->error($e->getMessage());
  }

  if ($deployed_certificates = json_decode($response->getBody(), TRUE)) {
    $certificates_map = [];
    foreach ($deployed_certificates['_embedded']['items'] as $item) {
      $certificates_map[$item['id']] = [
        'label'      => $item['label'],
        'expires_at' => $item['expires_at'],
        'active'     => $item['flags']['active'],
      ];
    }
    return $certificates_map;
  }
  return [];
}

/**
 * Prints response from Acquia Cloud API.
 */
function print_response_message($response_body, $cmd) {
  if ($response_body instanceof \Psr\Http\Message\ResponseInterface) {
    $response_body = $response_body->getBody()->getContents();
  }

  $response_body = json_decode($response_body, TRUE);

  if (array_key_exists('error', $response_body)) {
    $message = is_array($response_body['message'])
      ? json_encode($response_body['message'])
      : $response_body['message'];
    $cmd->error(new Exception($message));
  }

  print $response_body['message'] . PHP_EOL;
}
