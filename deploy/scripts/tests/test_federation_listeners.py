#!/usr/bin/env python3
"""Guard the deployment boundary without starting a container engine."""
from pathlib import Path
import unittest
import yaml

DEPLOY = Path(__file__).resolve().parents[2]


class FederationListenerTests(unittest.TestCase):
    def test_production_publishes_only_client_http_and_router_uses_internal_admin(self):
        services = yaml.safe_load((DEPLOY / 'docker-compose.yml').read_text())['services']
        federation = services['ramflux-federation']
        env = federation['environment']
        self.assertEqual(env['RAMFLUX_FEDERATION_PUBLIC_ADDR'], '0.0.0.0:18082')
        self.assertEqual(env['RAMFLUX_FEDERATION_ADMIN_ADDR'], '0.0.0.0:18084')
        self.assertIn('${RAMFLUX_FEDERATION_PUBLIC_PORT:-18082}:18082', federation['ports'])
        self.assertFalse(any(port.endswith(':18084') for port in federation['ports']))
        self.assertEqual(services['ramflux-router']['environment']['RAMFLUX_ROUTER_FEDERATION_FORWARD_URL'],
                         'http://ramflux-federation:18084/internal/home-node-migration/forward')

    def test_itest_control_is_separate_and_admin_host_override_is_loopback_only(self):
        services = yaml.safe_load((DEPLOY / 'docker-compose.itest.yml').read_text())['services']
        env = services['ramflux-federation']['environment']
        self.assertEqual(len({env[key] for key in ['RAMFLUX_FEDERATION_PUBLIC_ADDR',
                         'RAMFLUX_FEDERATION_ADMIN_ADDR', 'RAMFLUX_ITEST_FEDERATION_HTTP_ADDR']}), 3)
        override = yaml.safe_load((DEPLOY / 'docker-compose.itest.admin.yml').read_text())
        ports = override['services']['ramflux-federation']['ports']
        self.assertEqual(ports, ['127.0.0.1:${RAMFLUX_ITEST_FEDERATION_ADMIN_PORT:?test admin port required}:18084'])
