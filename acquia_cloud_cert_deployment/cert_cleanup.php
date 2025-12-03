#!/usr/bin/env php
<?php

require __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/common.php';

use League\OAuth2\Client\Provider\GenericProvider;
use GuzzleHttp\Client;
use Commando\Command;
use GuzzleHttp\Exception\ClientException;

$cmd = new Commando\Command();

// Only need environment ID
$cmd->option()->require()->referredToAs('Environment ID');

list($environment_id) = $cmd;

$secrets = extract_secrets($cmd);
$base_url = 'https://cloud.acquia.com/api/';
$provider = new GenericProvider([
  'clientId' => $secrets['token'],
  'clientSecret' => $secrets['secret'],
  'urlAccessToken' => 'https://accounts.acquia.com/api/auth/oauth/token',
]);

$accessToken = $provider->getAccessToken('client_credentials');
$client = new Client();

$certificates = get_deployed_certificates($environment_id, $client, $base_url, $cmd, $provider, $accessToken);
$now = new DateTimeImmutable('now', new DateTimeZone('UTC'));

foreach ($certificates as $cert_id => $meta) {
  if (!empty($meta['expires_at']) && $meta['active'] === true) {
    $expires_at = new DateTimeImmutable($meta['expires_at'], new DateTimeZone('UTC'));
    if ($expires_at < $now) {
      try {
        // Deactivate
        $api_method = "environments/{$environment_id}/ssl/certificates/{$cert_id}/actions/deactivate";
        $resp = $client->send($provider->getAuthenticatedRequest('POST', $base_url . $api_method, $accessToken, []));
        print_response_message($resp->getBody(), $cmd);

        // Delete
        $delete_method = "environments/{$environment_id}/ssl/certificates/{$cert_id}";
        $del_resp = $client->send($provider->getAuthenticatedRequest('DELETE', $base_url . $delete_method, $accessToken, []));
        print_response_message($del_resp->getBody(), $cmd);
      } catch (ClientException $e) {
        print $e->getMessage();
        print_response_message($e->getResponse(), $cmd);
      }
    }
  }
}
