#!/usr/bin/python
import psycopg2
import flask
import ldap

app = flask.Flask(__name__)
app.config.from_pyfile('settings.py')

con = psycopg2.connect(
    host = app.config['DATABASE']['host'],
    database = app.config['DATABASE']['database'],
    user = app.config['DATABASE']['user'],
    password = app.config['DATABASE']['password']
)


def authenticate(username, password):

    def _escape(s, wildcard=False):
        chars_to_escape = ['\\',',','=','+','<','>',';','"','\'','#','(',')','\0']

        if not wildcard:
            chars_to_escape.append('*')

        escape = lambda x,y: x.replace(y,'\%02X' % ord(y))

        return reduce(escape, chars_to_escape, s)


    def _format_dn(attr, with_base_dn = True):
        if with_base_dn:
            attr.extend(app.config['LDAP']['base_dn'])

        dn = ['%s=%s' % (item[0], _escape(item[1])) for item in attr]

        return ','.join(dn)

    ldap.protocol_version = 3
    l = ldap.initialize(app.config['LDAP']['host'])
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    try:
        user_dn = _format_dn([('uid', username)])
        l.simple_bind_s(user_dn, password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False


@app.route('/update/<user>/')
def update_domain(user):
    
    if not 'password' in flask.request.args:
        flask.abort(400)

    if 'ip' in flask.request.args:
        ip = flask.request.args['ip'] 
    else:
        ip = flask.request.remote_addr
    

    password = flask.request.args['password'] 
    if not authenticate(user, password):
        flask.abort(403)

    domain =  user + '.ddns.spline.de'

    cur = con.cursor()
    cur.execute(
        'UPDATE records SET content=%s, change_date=now() ' +
        'WHERE name=%s AND type=\'A\';', (ip, domain))

    if cur.rowcount < 1:
        cur.execute(
            'INSERT INTO records (domain_id, name, type, content, ttl, change_date) ' +
            'SELECT d.id, %s, \'A\', %s, 60, now() FROM domains d WHERE d.name = \'ddns.spline.de\'',
            (domain, ip)
        )
        
    conn.commit()    
    cur.close()
    
    return 204
    



if __name__ == '__main__':
    app.run(host = '::')
