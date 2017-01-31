#!/usr/bin/env python
"""
pdb_report.py
Created by Daniel Piekacz on 2017-01-25.
Updated on 2017-01-30.
https://gixtools.net
"""
import operator
import datetime
import ssl
import redis
import json

import pygal
import pygal_maps_world

from peeringdb import PeeringDB
from flask import Flask, request, render_template

from pdb_config import config


def is_valid_asn(s):
    try:
        asn = int(s)
        if ((asn > 0 and asn < 64496) or (asn > 131071 and asn < 397213)) and (asn != 23456):
            return True
        else:
            return False
    except ValueError:
        pass

    return False


def percent_formatter(x):
    return '{:.10g}%'.format(x)


def capacity_gb_formatter(x):
    return '{:,.10g} Gb'.format(x)


def capacity_tb_formatter(x):
    return '{:,.2f} Tb'.format(x)


def log(rdb, message, data):
    if config['debug']:
        tst = datetime.datetime.now().strftime(config['timestamp_format'])
        rdb.lpush('pdb_log', tst + ' > ' + message % (data))
        print tst + ' > ' + message % (data)


def pdb_report(asn):
    pdb = PeeringDB()
    rdb = redis.Redis()

    total_peering = 0
    total_peering_v4 = 0
    total_peering_v6 = 0
    total_capacity = 0

    peering_org = {}
    peering_table = {}
    peering_ixlan = {}
    ixlan_table = {}

    peering_map = {}
    peering_map_capacity = {}

    date_format = '%Y-%m-%d'
    date_current = datetime.datetime.today()

    # Searching for ASN in the local db
    log(rdb, 'Querying Redis DB for ASN %s', (asn))
    asn_info = rdb.get('as_' + str(asn))
    if not asn_info:
        # ASN not found
        log(rdb, 'ASN %s not found in DB', (asn))
        try:
            # Querying PeeringDB for the ASN
            log(rdb, 'Querying PeeringDB for ASN %s', (asn))
            pdb_resp = pdb.all('net', asn=asn, depth=2)
            if not pdb_resp:
                return render_template('error.html', error='No entry in PeeringDB for ASN ' + str(asn), message='That AS operator has not published details yet :(')
            else:
                asn_info = pdb_resp[0]
        except:
            return render_template('error.html', error='No entry in PeeringDB for ASN ' + str(asn), message='That AS operator has not published details yet :(')
        else:
            rdb.set('as_' + str(asn), json.dumps(asn_info))

    else:
        # ASN is cached
        log(rdb, 'ASN %s is cached', (asn))
        asn_info = json.loads(asn_info)

    log(rdb, '%s - ASN %s', (asn_info['name'], asn_info['asn']))

    # Total number of peering points
    total_peering = len(asn_info['netixlan_set'])

    # Walking through all IXLANs the ASN is connected to
    for peering in asn_info['netixlan_set']:
        # Total aggregated capacity
        total_capacity += peering['speed']

        # Counting IPv4 and IPv6 peering's
        if peering['ipaddr4']:
            total_peering_v4 += 1
        if peering['ipaddr6']:
            total_peering_v6 += 1

        # Searching for IX in the local db
        log(rdb, 'Querying Redis DB for IX %s', (peering['ix_id']))
        ix_info = rdb.get('ix_' + str(peering['ix_id']))
        if not ix_info:
            # IX not found
            log(rdb, 'IX ID %s not found in DB', (peering['ix_id']))

            # Querying PeeringDB for IX
            log(rdb, 'Querying PeeringDB for IX ID %s', (peering['ix_id']))
            ix_info = pdb.all('ix', id=peering['ix_id'], depth=2)[0]
            rdb.set('ix_' + str(peering['ix_id']), json.dumps(ix_info))
        else:
            # IX is cached
            log(rdb, 'IX %s is cached', (peering['ix_id']))
            ix_info = json.loads(ix_info)

        # Generating stats for IXLAN
        if peering['ixlan_id'] in peering_ixlan:
            # Stats already generated
            log(rdb, 'Stats ready for IXLAN %s', (peering['ixlan_id']))
        else:
            # Stats not found
            # Searching for IXLAN in the local db
            log(rdb, 'Querying Redis DB for IXLAN %s', (peering['ixlan_id']))
            ixlan_info = rdb.get('ixlan_' + str(peering['ixlan_id']))
            if not ixlan_info:
                # IXLAN not found
                log(rdb, 'IXLAN ID %s not found in DB', (peering['ixlan_id']))

                # Querying PeeringDB for IXLAN
                log(rdb, 'Querying PeeringDB for IXLAN ID %s', (peering['ixlan_id']))
                ixlan_info = pdb.all('ixlan', id=peering['ixlan_id'], depth=2)[0]
                rdb.set('ixlan_' + str(peering['ixlan_id']), json.dumps(ixlan_info))
            else:
                # IXLAN is cached
                log(rdb, 'IXLAN %s is cached', (peering['ixlan_id']))
                ixlan_info = json.loads(ixlan_info)

            log(rdb, 'Generating stats for IXLAN %s', (peering['ixlan_id']))

            # Counting IXLAN members' types and connected capacity
            peering_ixlan[peering['ixlan_id']] = {}
            peering_ixlan[peering['ixlan_id']]['name'] = peering['name']
            peering_ixlan[peering['ixlan_id']]['peer_transit_access'] = 0
            peering_ixlan[peering['ixlan_id']]['peer_content'] = 0
            peering_ixlan[peering['ixlan_id']]['peer_enterprise'] = 0
            peering_ixlan[peering['ixlan_id']]['peer_other'] = 0
            peering_ixlan[peering['ixlan_id']]['capacity_transit_access'] = 0
            peering_ixlan[peering['ixlan_id']]['capacity_content'] = 0
            peering_ixlan[peering['ixlan_id']]['capacity_enterprise'] = 0
            peering_ixlan[peering['ixlan_id']]['capacity_other'] = 0

            # Walking through all members connected to IXP network (we need those details to see speed of each peering)
            isp_list = {}
            for isp in ixlan_info['net_set']:
                # Counting IXLAN members only once. PeeringDB returns members ID many time depends on number of peering links.
                if isp['asn'] not in isp_list:
                    if isp['info_type'] == 'NSP':
                        peering_ixlan[peering['ixlan_id']]['peer_transit_access'] += 1
                    elif isp['info_type'] == 'Cable/DSL/ISP':
                        peering_ixlan[peering['ixlan_id']]['peer_transit_access'] += 1
                    elif isp['info_type'] == 'Content':
                        peering_ixlan[peering['ixlan_id']]['peer_content'] += 1
                    elif isp['info_type'] == 'Enterprise':
                        peering_ixlan[peering['ixlan_id']]['peer_enterprise'] += 1
                    else:
                        peering_ixlan[peering['ixlan_id']]['peer_other'] += 1

                    # Querying local cache for ASN
                    log(rdb, 'Querying Redis DB for ASN %s', (isp['asn']))
                    isp_info = rdb.get('as_' + str(isp['asn']))
                    if not isp_info:
                        # ASN not found
                        log(rdb, 'ASN %s not found in DB', (isp['asn']))

                        # Querying PeeringDB for ASN
                        log(rdb, 'Querying PeeringDB for ASN %s', (isp['asn']))
                        isp_info = pdb.all('net', asn=isp['asn'], depth=2)[0]
                        rdb.set('as_' + str(isp['asn']), json.dumps(isp_info))
                    else:
                        # ASN is cached
                        log(rdb, 'ASN %s is cached', (isp['asn']))
                        isp_info = json.loads(isp_info)

                    # Accounting total capacity connected to IXLAN grouped by type of member
                    for isp_netixlan_info in isp_info['netixlan_set']:
                        if isp_netixlan_info['ixlan_id'] == peering['ixlan_id']:
                            if isp_info['info_type'] == 'NSP':
                                peering_ixlan[peering['ixlan_id']]['capacity_transit_access'] += isp_netixlan_info['speed']
                            elif isp_info['info_type'] == 'Cable/DSL/ISP':
                                peering_ixlan[peering['ixlan_id']]['capacity_transit_access'] += isp_netixlan_info['speed']
                            elif isp_info['info_type'] == 'Content':
                                peering_ixlan[peering['ixlan_id']]['capacity_content'] += isp_netixlan_info['speed']
                            elif isp_info['info_type'] == 'Enterprise':
                                peering_ixlan[peering['ixlan_id']]['capacity_enterprise'] += isp_netixlan_info['speed']
                            else:
                                peering_ixlan[peering['ixlan_id']]['capacity_other'] += isp_netixlan_info['speed']

                isp_list[isp['asn']] = ""

            log(rdb, 'Generating stats for IXLAN %s complete', (isp_netixlan_info['ixlan_id']))

        # Accounting numer of peering's and total connected capacity in each country
        if ix_info['country'].lower() in peering_map:
            peering_map[ix_info['country'].lower()] += 1
            peering_map_capacity[ix_info['country'].lower()] += peering['speed'] / 1000
        else:
            peering_map[ix_info['country'].lower()] = 1
            peering_map_capacity[ix_info['country'].lower()] = peering['speed'] / 1000

        # Couting unique IXP organizations/operators
        if ix_info['org_id'] in peering_org:
            # IXP operator already counted
            log(rdb, 'IXP org ID %s already counted', (ix_info['org_id']))
        else:
            # A new IXP operator
            log(rdb, 'IXP org ID %s not yet counted', (ix_info['org_id']))
            peering_org[ix_info['org_id']] = ix_info['name_long']

        log(rdb, '%s - %s - %s - %s', (peering['name'].encode('utf8'), ix_info['name'].encode('utf8'), ix_info['org_id'], peering['speed']))

        # Creating new entry for each unique IXP name
        if peering['name'] not in peering_table:
            peering_table[peering['name']] = {}

        # Calculating difference between current date and PeeringDB timestamps in days
        date_created = datetime.datetime.strptime(peering['created'][0:10], date_format)
        date_updated = datetime.datetime.strptime(peering['updated'][0:10], date_format)
        date_created_diff = abs((date_current - date_created).days)
        date_updated_diff = abs((date_current - date_updated).days)

        # peering_table[peering['name']]['name'] = peering['name']
        peering_table[peering['name']][peering['id']] = {}
        peering_table[peering['name']][peering['id']]['status'] = peering['status']
        peering_table[peering['name']][peering['id']]['speed'] = peering['speed']
        if peering['is_rs_peer']:
            peering_table[peering['name']][peering['id']]['rs'] = 'Yes'
        else:
            peering_table[peering['name']][peering['id']]['rs'] = 'No'

        if peering['ipaddr4']:
            peering_table[peering['name']][peering['id']]['ip4'] = peering['ipaddr4']
        else:
            peering_table[peering['name']][peering['id']]['ip4'] = 'N/A'

        if peering['ipaddr6']:
            peering_table[peering['name']][peering['id']]['ip6'] = peering['ipaddr6']
        else:
            peering_table[peering['name']][peering['id']]['ip6'] = 'N/A'

        # Removing time from PeeringDB timestamps
        peering_table[peering['name']][peering['id']]['created'] = peering['created'][0:10]
        peering_table[peering['name']][peering['id']]['updated'] = peering['updated'][0:10]
        if date_created_diff <= config['days']:
            peering_table[peering['name']][peering['id']]['created_warn'] = True
        else:
            peering_table[peering['name']][peering['id']]['created_warn'] = False
        if date_updated_diff <= config['days']:
            peering_table[peering['name']][peering['id']]['updated_warn'] = True
        else:
            peering_table[peering['name']][peering['id']]['updated_warn'] = False

        ixlan_table[peering['name']] = peering['ixlan_id']

    # Sort peering's table based on IXP name
    log(rdb, 'Sorting peering table for ASN %s', (asn))
    peering_table = sorted(peering_table.items(), key=operator.itemgetter(0))

    # Generating charts for IXLANs
    for ix in peering_ixlan:
        log(rdb, 'Generating network types chart for IXLAN %s', (ix))

        # Calculating total number of members and total connected by members capacity
        total_number_of_members = peering_ixlan[ix]['peer_transit_access'] + peering_ixlan[ix]['peer_content'] + peering_ixlan[ix]['peer_enterprise'] + peering_ixlan[ix]['peer_other']
        total_capacity_of_members = peering_ixlan[ix]['capacity_transit_access'] + peering_ixlan[ix]['capacity_content'] + peering_ixlan[ix]['capacity_enterprise'] + peering_ixlan[ix]['capacity_other']

        # Generating chart showing number of members grouped by network type
        pie_chart_number_url = 'static/ixlan_' + str(ix) + '_number.svg'
        pie_chart_number = pygal.Bar()
        pie_chart_number.title = 'Network types at ' + peering_ixlan[ix]['name'] + ' [%]\n Total number of unique members: ' + str(total_number_of_members)
        pie_chart_number.value_formatter = percent_formatter
        pie_chart_number.add('NSP/ISP', 100 * peering_ixlan[ix]['peer_transit_access'] / total_number_of_members)
        pie_chart_number.add('Content', 100 * peering_ixlan[ix]['peer_content'] / total_number_of_members)
        pie_chart_number.add('Enterprise', 100 * peering_ixlan[ix]['peer_enterprise'] / total_number_of_members)
        pie_chart_number.add('Other', 100 * peering_ixlan[ix]['peer_other'] / total_number_of_members)
        pie_chart_number.render_to_file(pie_chart_number_url)

        # Generating chart showing total capacity grouped by network type
        pie_chart_capacity_url = 'static/ixlan_' + str(ix) + '_capacity.svg'
        pie_chart_capacity = pygal.Bar()
        pie_chart_capacity.value_formatter = capacity_gb_formatter
        pie_chart_capacity.title = 'Networt types at ' + peering_ixlan[ix]['name'] + ' [Gb]\n Total capacity of members: ' + capacity_gb_formatter(total_capacity_of_members / 1000)
        pie_chart_capacity.add('NSP/ISP', peering_ixlan[ix]['capacity_transit_access'] / 1000)
        pie_chart_capacity.add('Content', peering_ixlan[ix]['capacity_content'] / 1000)
        pie_chart_capacity.add('Enterprise', peering_ixlan[ix]['capacity_enterprise'] / 1000)
        pie_chart_capacity.add('Other', peering_ixlan[ix]['capacity_other'] / 1000)
        pie_chart_capacity.render_to_file(pie_chart_capacity_url)

    # Calculating total number of unique peering operators and total capacity in Gb & Tb
    total_unique_org = len(peering_org)
    total_capacity_gb = total_capacity / 1000
    total_capacity_tb = round(float(total_capacity) / (1000 * 1000), 2)

    log(rdb, 'AS %s total number of peering points: %s', (asn, total_peering))
    log(rdb, 'AS %s total number of unique organization peering: %s', (asn, total_unique_org))

    # Generating world map with number and location of peering's
    log(rdb, 'Generating world map for AS %s with number of peering locations', (asn))
    map_number_url = 'static/as' + asn + '_map_number.svg'
    map_number = pygal.maps.world.World()
    map_number.title = 'World map with number of peering locations'
    map_number.add('Peerings', peering_map)
    map_number.render_to_file(map_number_url)

    # Generating world map with total capacity of peering's
    log(rdb, 'Generating world map for AS %s with total capacity', (asn))
    map_capacity_url = 'static/as' + asn + '_map_capacity.svg'
    map_capacity = pygal.maps.world.World()
    map_capacity.title = 'World map with total capacity'
    map_capacity.value_formatter = capacity_gb_formatter
    map_capacity.add('Capacity', peering_map_capacity)
    map_capacity.render_to_file(map_capacity_url)

    # Generating gauge graph with percentage of IPv4 and IPv6 peering's
    log(rdb, 'Generating gauge graph with percentage of IPv4 and IPv6 peering for AS %s', (asn))
    gauge_v46_url = 'static/as' + asn + '_v46.svg'
    gauge_v46 = pygal.SolidGauge(inner_radius=0.70, half_pie=True)
    gauge_v46.value_formatter = percent_formatter

    # Checking if accounted total capacity > 0. Some ASNs do publish any details about public peerings
    if total_peering > 0:
        gauge_v46.add('IPv4', [{'value': 100 * total_peering_v4 / total_peering, 'max_value': 100}])
        gauge_v46.add('IPv6', [{'value': 100 * total_peering_v6 / total_peering, 'max_value': 100}])
    else:
        gauge_v46.add('IPv4', [{'value': 0, 'max_value': 100}])
        gauge_v46.add('IPv6', [{'value': 0, 'max_value': 100}])
    gauge_v46.render_to_file(gauge_v46_url)

    # Rendering HTML template with the provided data
    log(rdb, 'Rendering HTML template with report for AS %s', (asn))
    pdb_report = render_template(
        'report.html',
        asn=asn,
        asn_name=asn_info['name'],
        total_peering=total_peering,
        total_unique_org=total_unique_org,
        total_capacity_gb=capacity_gb_formatter(total_capacity_gb),
        total_capacity_tb=capacity_tb_formatter(total_capacity_tb),
        peering=peering_table,
        ixlan=ixlan_table,
        days=config['days'],
        peering_v46="/" + gauge_v46_url,
        map_number="/" + map_number_url,
        map_capacity="/" + map_capacity_url
    )

    log(rdb, 'Report for AS %s has been generated', (asn))

    return pdb_report


if __name__ == '__main__':
    app = Flask(__name__)
    rdb = redis.Redis()

    @app.after_request
    def add_header(r):
        """
        Add headers to both force latest IE rendering engine or Chrome Frame,
        and also to do cache the rendered page.
        """
        r.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        r.headers['Pragma'] = 'no-cache'
        r.headers['Expires'] = '0'
        r.headers['Cache-Control'] = 'public, max-age=0'

        return r

    @app.route('/')
    def index():
        log(rdb, 'Main page access from %s', (request.remote_addr))

        return render_template('about.html', days=config['days'])

    @app.route('/pdb-flushredis/')
    def flushredis():
        if config['redis_flush_allowed']:
            log(rdb, 'Redis DB flush request from %s', (request.remote_addr))
            rdb.flushall()
            return render_template('error.html', error='Redis DB flushed', message='')
        else:
            log(rdb, 'Redis DB flush disabled %s', (request.remote_addr))
            return render_template('error.html', error='Redis DB flush disabled', message='')

    @app.route('/pdb-eventlog/')
    def eventlog():
        log(rdb, 'Eventlog request from %s', (request.remote_addr))

        return render_template('eventlog.html', error='Eventlog', eventlog_entries=config['eventlog_entries'])

    @app.route('/pdb-eventlog-data/')
    def eventlog_data():
        log(rdb, 'Eventlog Data request from %s', (request.remote_addr))

        log(rdb, 'Pulling %s log records from Redis DB', (config['eventlog_entries']))
        logs = rdb.lrange('pdb_log', 0, config['eventlog_entries'])

        response = app.response_class(
            response=json.dumps(logs),
            status=200,
            mimetype='application/json'
        )

        return response

    @app.route('/asn/<asn>/')
    def asn(asn=''):
        if is_valid_asn(asn):
            log(rdb, 'PeeringDB Report request from %s for ASN %s', (request.remote_addr, asn))
            report = pdb_report(asn)

            return report

        else:
            log(rdb, 'PeeringDB Report request from %s for invalid ASN %s', (request.remote_addr, asn))

            return render_template('error.html', error='Invalid ASN provided: ' + str(asn), message='ASNs are accepted only from the ranges 1-23455, 23457-64495 and 131072-397212')

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(config['ssl_crt'], config['ssl_key'])
    context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA')
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    context.options |= ssl.OP_NO_COMPRESSION

    app.run(debug=config['debug'], host=config['http_ip'], port=config['http_port'], ssl_context=context, threaded=True)
