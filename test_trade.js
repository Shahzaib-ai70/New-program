
async function test() {
    const api = 'http://localhost:3001';
    
    // 1. Create/Reset user
    const user = 'testuser_' + Date.now();
    await fetch(`${api}/api/register`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username: user, password: '123' })
    });

    // Set balance to 1000
    await fetch(`${api}/api/admin/users/balance`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username: user, balance: 1000 })
    });

    // Check balance
    let res = await fetch(`${api}/api/me`, { headers: { 'x-user': user } });
    let data = await res.json();
    console.log(`Initial Balance: ${data.balance}`); // Should be 1000

    // 2. Set Win Side to 'long'
    await fetch(`${api}/api/admin/winside`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ side: 'long' })
    });

    // 3. Execute WIN trade (Long, 100, 50%)
    console.log("Executing WIN trade...");
    res = await fetch(`${api}/api/trade`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: user,
            symbol: 'BTC',
            side: 'long',
            amount: 100,
            percent: 50
        })
    });
    data = await res.json();
    console.log("Win Trade Result:", data);

    // Check balance
    res = await fetch(`${api}/api/me`, { headers: { 'x-user': user } });
    data = await res.json();
    console.log(`Balance after WIN: ${data.balance}`); // Should be 1050

    // 4. Execute LOSE trade (Short, 100, 50%)
    console.log("Executing LOSE trade...");
    res = await fetch(`${api}/api/trade`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: user,
            symbol: 'BTC',
            side: 'short',
            amount: 100,
            percent: 50
        })
    });
    data = await res.json();
    console.log("Lose Trade Result:", data);

    // Check balance
    res = await fetch(`${api}/api/me`, { headers: { 'x-user': user } });
    data = await res.json();
    console.log(`Balance after LOSE: ${data.balance}`); // Should be 950 (1050 - 100)
}

test();
