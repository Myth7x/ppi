from flask import Flask, request, jsonify, render_template, url_for
from threading import Thread
import time

from db import init_db, get_db, rules

PACKET_LOG = []
DIVERT_FILTER = "tcp.DstPort == 10375 or tcp.SrcPort == 10375"
DIVERT_THREAD = None
ENABLED = False
RULES = []

FAPP = Flask(__name__, template_folder='templates')

def create_app() -> Flask:
    global FAPP
    FAPP.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
    from flask_cors import CORS
    CORS(FAPP)

    init_db(FAPP)
    return FAPP



def divert_thread():
    global PACKET_LOG, DIVERT_FILTER, ENABLED, RULES
    import pydivert
    with pydivert.WinDivert(DIVERT_FILTER) as w:
        if not ENABLED:
            return
        try:
            for packet in w:
                if not ENABLED:
                    return
                packet.time = time.time()

                # Apply rules
                send_packet = True
                for rule in RULES:

                    match rule['rule_type']:
                        case 'Modify': # Modify
                            #logging.info(f"comparing {rule['rule']['target']} to {packet.payload}")
                            if bytes(rule['rule']['target'], 'utf-8') in packet.payload:
                               # logger.info(f"Matched Modify rule: {rule['rule']}")

                                match rule['rule']['type']:
                                    case 'Replace':
                                        packet.payload = packet.payload.replace(rule['rule']['target'].encode(), rule['rule']['data'].encode())
                                        #logger.info(f"Replaced {rule['rule']['target']} with {rule['rule']['data']}")
                                    case 'Prepend':
                                        packet.payload = rule['rule']['data'].encode() + packet.payload
                                    case 'Append':
                                        packet.payload = packet.payload + rule['rule']['data'].encode()
                                    case 'Remove':
                                        packet.payload = packet.payload.replace(rule['rule']['target'].encode(), b'')
                                    case _:
                                        print("Unknown rule type")
                                        send_packet = False
                                        break
                                setattr(packet, 'rule_applied', rule)


                if not send_packet:
                    continue


                PACKET_LOG.append(packet)
                try:
                    w.send(packet)
                except:
                    pass
        except KeyboardInterrupt:
            w.close()
            return


@FAPP.route('/get_divert_config', methods=['GET'])
def get_divert_config():
    global DIVERT_FILTER, ENABLED
    return jsonify({'filter': DIVERT_FILTER, 'enabled': ENABLED})


@FAPP.route('/set_divert_config', methods=['POST'])
def set_divert_config():
    global DIVERT_FILTER, DIVERT_THREAD, ENABLED
    DIVERT_FILTER = request.json['filter']
    ENABLED = request.json['enabled']
    if ENABLED is not None:
        DIVERT_THREAD.join()
        print("Divert thread joined")

    DIVERT_THREAD = Thread(target=divert_thread, daemon=True)
    DIVERT_THREAD.start()
    return jsonify({'filter': DIVERT_FILTER, 'enabled': ENABLED})


@FAPP.route('/get_packet_list', methods=['GET'])
def get_packet_list():
    global PACKET_LOG, ENABLED
    data_list = []
    for packet in PACKET_LOG:
        if not ENABLED: break
        if not 0x02 or 0xd2 in packet.payload: continue
        data_list.append({
            'timestamp': packet.time,
            'src_addr': packet.src_addr,
            'dst_addr': packet.dst_addr,
            'payload': f'({len(packet.payload)})' + '|' + ' '.join([f'{x:02x}' for x in packet.payload]),
            'rule_applied': packet.rule_applied if hasattr(packet, 'rule_applied') else None,
        })
    PACKET_LOG = []
    return jsonify(data_list)


@FAPP.route('/set_rules', methods=['POST'])
def set_rules():
    db = get_db()
    db.session.query(rules).delete()
    for rule in request.json:
        db.session.add(rules(
            active=rule['active'],
            name=rule['name'],
            direction=0 if 'direction' not in rule or rule['direction'] == 'Outbound' else 1,
            rule_type=rule['type'],
            rule=rule['type-config']
        ))
    db.session.commit()
    return jsonify({'success': True})


@FAPP.route('/get_rules', methods=['GET'])
def get_rules():
    db = get_db()
    rules_list = []
    for rule in db.session.query(rules).all():
        rules_list.append({
            'active': rule.active,
            'name': rule.name,
            'direction': 'Outbound' if rule.direction == 0 else 'Inbound',
            'type': rule.rule_type,
            'type-config': rule.rule
        })
    return jsonify(rules_list)


@FAPP.route('/<path:path>')
def app(path):
    return render_template("app.html", path=path)


@FAPP.context_processor
def override_url_for():
    sys_messages = []
    if not get_db().engine:
        sys_messages.append({
            'timestamp': time.time(),
            'type': 'error',
            'message': 'Database not connected'
        })
    return dict(url_for=url_for,render_template=render_template, system_messages=sys_messages)


@FAPP.before_request
def before_request():
    global RULES
    db = get_db()
    if not db.engine:
        return
    RULES = [{'active': rule.active, 'name': rule.name, 'direction': rule.direction, 'rule_type': rule.rule_type, 'rule': rule.rule} for rule in db.session.query(rules).all()]
