const instance = require('./utils/client');
const dbUtils = require('./utils/db');

const doLogin = () => instance.get('/?action=test-auth');
const doLogout = () => instance.get('/?action=logout');

beforeEach(() => {
    return Promise.all([
        dbUtils.clearDatabase(),
        doLogout(),
    ]);
});

test.skip('snapshot /?action=auth without auth', async () => {
    try {
        const response = await instance.get('/?action=auth');
        fail();
    } catch (e) {
        expect(e.response.status).toBe(401);
        expect(e.response.data).toMatchSnapshot();
    }
});

test('snapshot /?action=auth with auth', async () => {
    await doLogin();
    const response = await instance.get('/?action=auth');
    expect(response.data).toMatchSnapshot();
});

test('snapshot /?action=admin-questions without auth', async () => {
    try {
        const response = await instance.get('/?action=admin-questions');
        fail();
    } catch (e) {
        expect(e.response.status).toBe(401);
        expect(e.response.data).toMatchSnapshot();
    }
});

test('snapshot /?action=admin-questions with auth', async () => {
    await doLogin();
    const response = await instance.get('/?action=admin-questions');
    expect(response.data).toMatchSnapshot();
});

test('snapshot /?action=admin-questions&page=2', async () => {
    await doLogin();
    const response = await instance.get('/?action=admin-questions&page=2');
    expect(response.data).toMatchSnapshot();
});


test('snapshot /?action=admin-question n.58 without auth', async () => {
    try {
        const response = await instance.get('/?action=admin-question&id=58');
        fail();
    } catch (e) {
        expect(e.response.status).toBe(401);
        expect(e.response.data).toMatchSnapshot();
    }
});

test('snapshot /?action=admin-question n. 58 with auth', async () => {
    await doLogin();
    const response = await instance.get('/?action=admin-question&id=58');
    expect(response.data).toMatchSnapshot();
});

test.skip('snapshot /?action=admin-suggest without auth', async () => {
    try {
        const response = await instance.get('/?action=admin-suggest&name=Black');
        fail();
    } catch (e) {
        expect(e.response.status).toBe(401);
        expect(e.response.data).toMatchSnapshot();
    }
});

test('snapshot /?action=admin-suggest with auth', async () => {
    await doLogin();
    const response = await instance.get('/?action=admin-suggest&name=Black');
    expect(response.data).toMatchSnapshot();
});

test('snapshot /?action=admin-translations without auth', async () => {
    try {
        const response = await instance.get('/?action=admin-translations&language=2');
        fail();
    } catch (e) {
        expect(e.response.status).toBe(401);
        expect(e.response.data).toMatchSnapshot();
    }
});

test('snapshot /?action=admin-translations with auth', async () => {
    await doLogin();
    const response = await instance.get('/?action=admin-translations&language=2');
    expect(response.data).toMatchSnapshot();
});

test('snapshot /?action=admin-users without auth', async () => {
    try {
        const response = await instance.get('/?action=admin-users');
        fail();
    } catch (e) {
        expect(e.response.status).toBe(401);
        expect(e.response.data).toMatchSnapshot();
    }
});

test('snapshot /?action=admin-users with auth', async () => {
    await doLogin();
    const response = await instance.get('/?action=admin-users');
    expect(response.data).toMatchSnapshot();
});

test('snapshot /?action=admin-saveuser without auth', async () => {
    try {
        const response = await instance.post('/?action=admin-saveuser', {
            name: 'John Doe',
            email: 'john.doe@gmail.com',
            role: 'editor',
            languages: ['1', '2'],
        });
        fail();
    } catch (e) {
        expect(e.response.status).toBe(401);
        expect(e.response.data).toMatchSnapshot();
    }
});

test('snapshot /?action=admin-saveuser with auth', async () => {
    await doLogin();
    const response = await instance.post('/?action=admin-saveuser', {
        name: 'John Doe',
        email: 'john.doe@gmail.com',
        role: 'editor',
        languages: ['1', '2'],
    });
    expect(response.data).toMatchSnapshot();
});
