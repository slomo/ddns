#!/usr/bin/python
import psycopg2
import flask


app = flask.Flask(__name__)
app.config.from_pyfile('settings.py')

con = psycopg2.connect(
    host = app.config['DATABASE']['host'],
    database = app.config['DATABASE']['database'],
    user = app.config['DATABASE']['user'],
    password = app.config['DATABASE']['password']
)


def authenticate(username, password):
    ldap.protocol_version = 3
    l = ldap.initialize(app.config['LDAP']['host'])
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    try:
        user_dn = self._format_dn([('uid', username)])
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
        'UPDATE records SET content=%s, change_date=now()' +
        'WHERE name=%s, type="A";', (ip, domain))

    if cur.rowcount < 1:
        cur.execute(
            'INSERT INTO records (domain_id, name, type, content, ttl, change_date) ' +
            'SELECT d.id, %s, "A", %s, 60, now() FROM domains d WHERE d.name = "ddns.spline.de"',
            (domain, ip)
        )
        
    conn.commit()    
    cur.close()
    
    return 204
    



if __name__ == '__main__':
    app.run(host = '::')
