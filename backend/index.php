<?php
require("config.php");
define('MONTH', 60*60*24*30);
// server should keep session data for AT LEAST 1 month
ini_set('session.gc_maxlifetime', MONTH);
// each client should remember their session id for EXACTLY 1 month
session_set_cookie_params(MONTH);
session_start();
$db2 = new PDO(sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', DB_HOST, DB_NAME), DB_USER, DB_PASS, [
  PDO::ATTR_EMULATE_PREPARES   => false, // turn off emulation mode for "real" prepared statements
  PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, //turn on errors in the form of exceptions
  PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, //make the default fetch be an associative array
]);
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
$db->set_charset("utf8");

header("Content-type: application/json");

// Authenticate the user through the Google API and return their data
function auth($db, $token = "") {
  global $db2;

  if(array_key_exists('auth', $_SESSION)) {
    $email = $_SESSION['auth'];
    $query = $db2->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
    $query->execute([$email]);

    $user = $query->fetch();
    if(!$user) {
      header('HTTP/1.0 401 Unauthorized');
      return ['error' => 'No account found'];
    }

    $user['languages'] = $user['languages'] ? array_map('intval', explode(',', $user['languages'])) : [];

    return $user;
  }

  if($token) {
    $postData = "code=".urlencode($token).
                "&client_id=".urlencode(GAPPS_CLIENTID).
                "&client_secret=".urlencode(GAPPS_CLIENTSECRET).
                "&redirect_uri=".urlencode(GAPPS_REDIRECT).
                "&grant_type=authorization_code";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://www.googleapis.com/oauth2/v3/token");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,true);
    $result = json_decode(curl_exec($ch));
    curl_close($ch);

    if($result->error) {
      return ['error' => 'invalid_token'];
    }

    $token = $result->access_token;
    $userinfo = json_decode(file_get_contents("https://www.googleapis.com/oauth2/v2/userinfo?access_token=".$token));

    if($userinfo->verified_email) {
      $_SESSION['auth'] = $userinfo->email;
      return auth($db);
    }

    return ['error' => 'invalid_email'];
  }

  $url = 'https://accounts.google.com/o/oauth2/auth?'.
    'scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email' .
    '&response_type=code' .
    '&redirect_uri='  . urlencode(GAPPS_REDIRECT) .
    '&client_id=' . urlencode(GAPPS_CLIENTID);

  return ['login' => $url];
}

// get a list of all questions with sets and languages
function getQuestions($db) {
  global $db2;
  // TODO: remove `GROUP BY qc.card_id`
  $query = $db2->query('
    SELECT q.id, q.difficulty, GROUP_CONCAT(DISTINCT set_id) sets, GROUP_CONCAT(DISTINCT qto.language_id) languages
    FROM questions q
    LEFT JOIN question_cards qc ON qc.question_id = q.id
    LEFT JOIN card_sets cs ON cs.card_id = qc.card_id
    LEFT JOIN sets s ON s.id = cs.set_id
    LEFT JOIN question_translations qt ON qt.question_id = q.id AND qt.language_id = 1
    LEFT JOIN question_translations qto ON qto.question_id = q.id AND qto.changedate >= qt.changedate
    WHERE s.regular = 1 AND q.live = 1
    GROUP BY q.id, qc.card_id
  ');

  $questions = [];
  while($row = $query->fetch()) {
    if(!array_key_exists($row['id'], $questions)) {
      $questions[$row['id']] = [
        'id' => $row['id'],
        'difficulty' => $row['difficulty'],
        // TODO: change `cards` property to `sets`, checking on frontend too
        'cards' => [],
        'languages' => array_map('intval', explode(',', $row['languages'])),
      ];
    }

    $questions[$row['id']]['cards'][] = array_map('intval', explode(',', $row['sets']));
  }

  return array_values($questions);
}

// get a single question with cards and texts
function getQuestion($db, $id = false, $lang = false) {
  global $db2;

  // if $id or $lang are not provided
  // return empty array
  // TODO: probably we should return 404
  if(!$id || !$lang) {
    return [];
  }

  $questionStmt = $db2->prepare(
    'SELECT q.*, qt.question, qt.answer, IF(qto.changedate > qt.changedate, true, false) as outdated
    FROM questions q
    LEFT JOIN question_translations qt ON qt.question_id = q.id AND qt.language_id = :lang
    LEFT JOIN question_translations qto ON qto.question_id = q.id AND qto.language_id = 1
    WHERE q.id = :question
    LIMIT 1'
  );

  $questionStmt->execute([
    'lang' => $lang,
    'question' => $id,
  ]);

  $question = $questionStmt->fetch();

  // if question/lang doesn't exist
  // return empty array
  // TODO: probably we should return 404
  if(!$question) {
    return [];
  }

  $output = [
    // TODO: strip_tags on creation, non every get
    'question' => strip_tags($question['question']),
    'answer' => strip_tags($question['answer']),
    'metadata' => [
      'live' => !!$question['live'],
      'outdated' => !!$question['outdated'],
      'id' => $question['id'],
      'difficulty' => $question['difficulty'],
    ],
    'cards' => [],
  ];

  $cardsStmt = $db2->prepare(
    'SELECT c.*, IFNULL(ct.name, c.name) name, c.name name_en, IFNULL(ct.multiverseid, c.multiverseid) multiverseid
    FROM cards c
    JOIN question_cards qc ON qc.card_id = c.id
    LEFT JOIN card_translations ct ON ct.card_id = c.id AND ct.language_id = :lang
    WHERE qc.question_id = :question
    ORDER BY qc.sort ASC, c.layout, name'
  );

  $cardsStmt->execute([
    'lang' => $lang,
    'question' => $id,
  ]);

  while($card = $cardsStmt->fetch()) {
    $card['text'] = nl2br($card['text']);

    // Do we really need to remove empty fields?
    $card = array_filter($card, function ($value, $field) {
      return !($value === "" || $value === null || $field == 'id');
    }, ARRAY_FILTER_USE_BOTH);

    $output['cards'][] = $card;
  }

  return $output;
}

// get a list of sets
function getSets($db) {
  global $db2;
  $query = $db2->query('SELECT id, name, code, releasedate, standard, modern FROM sets WHERE regular = 1 ORDER BY releasedate DESC');

  return $query->fetchAll();
}

// get all the data for offline mode
function getQuestionsAndCards($db) {
  global $db2;

  $start_time = microtime(TRUE);

  // All questions
  $questions = [];

  $query = $db2->query('
    SELECT qt.*
    FROM questions q
    LEFT JOIN question_translations qt ON qt.question_id = q.id
    WHERE q.live = 1
  ');
  while($row = $query->fetch()) {
    if(!array_key_exists($row['question_id'], $questions)) {
      $questions[$row['question_id']] = ['cards' => []];
    }

    $questions[$row['question_id']][$row['language_id']] = [
      'question' => $row['question'],
      'answer' => $row['answer'],
    ];
  }

  // All cards
  $cards = [];
  // I don't use GROUP CONCAT to avoid overload on database
  $query = $db2->query('
    SELECT c.*, qc.question_id
    FROM cards as c
    JOIN question_cards as qc ON qc.card_id = c.id
    JOIN questions as q ON q.id = qc.question_id
    WHERE q.live = 1
    ORDER BY qc.sort ASC, c.layout, c.name ASC
  ');
  $end_time = microtime(TRUE);

  while($row = $query->fetch()) {
    if(!array_key_exists($row['id'], $cards)) {
      // Do we really need to remove empty fields?
      $cards[$row['id']] = array_filter($row, function ($value, $field) {
        return !($value === "" || $value === null || $field === 'id' || $field === 'question_id');
      }, ARRAY_FILTER_USE_BOTH);
    }

    if(!in_array($row['id'], $questions[$row['question_id']]['cards'])) {
      $questions[$row['question_id']]['cards'][] = $row['id'];
    }
  }

  // fetch translations only for used cards
  $query = $db2->query('
    SELECT ct.*
    FROM card_translations as ct
    WHERE card_id IN (' . implode(', ', array_keys($cards)) . ')
  ');

  while($row = $query->fetch()) {
    $cards[$row['card_id']]['translations'][$row['language_id']] = $row['name'];
  }

  $end_time = microtime(TRUE);

  return [
    'questions' => $questions,
    'cards' => $cards,
  ];
}

function getAdminQuestions($db, $page = 0) {
  global $db2;

  $user = auth($db);

  if(!array_key_exists('role', $user) || !in_array($user['role'], ['admin', 'editor', 'translator'])) {
    header('HTTP/1.0 401 Unauthorized');
    return [];
  }

  $pageSize = QUESTIONS_PER_PAGE;
  $start = intval($page) * $pageSize;
  // TODO: avoid too many join
  $query = $db2->query("SELECT SQL_CALC_FOUND_ROWS q.*,
    GROUP_CONCAT(DISTINCT c.name ORDER BY sort ASC SEPARATOR '|') cards,
    GROUP_CONCAT(DISTINCT qt2.language_id) languages,
    GROUP_CONCAT(DISTINCT qt3.language_id) outdated
    FROM questions q
    LEFT JOIN question_cards qc ON qc.question_id = q.id
    LEFT JOIN cards c ON qc.card_id = c.id
    LEFT JOIN question_translations qt ON qt.question_id = q.id AND qt.language_id = 1
    LEFT JOIN question_translations qt2 ON qt2.question_id = q.id
    LEFT JOIN question_translations qt3 ON qt3.question_id = q.id AND qt3.changedate < qt.changedate
    GROUP BY q.id
    ORDER BY q.id DESC
    LIMIT $start, $pageSize");

  $questions = [];

  while($row = $query->fetch()) {
    $row['live'] = !!$row['live'];
    $row['cards'] = explode('|', $row['cards']);
    $row['languages'] = array_map('intval', explode(',', $row['languages']));
    $row['outdated'] = $row['outdated'] ? array_map('intval', explode(',', $row['outdated'])) : [];

    $questions[] = $row;
  }

  $queryCount = $db2->query('SELECT FOUND_ROWS() as rows');
  $count = $queryCount->fetch()['rows'];

  return [
    'questions' => $questions,
    'pages' => ceil($count / $pageSize)
  ];
}

function getAdminQuestion($db, $id) {
  global $db2;

  $user = auth($db);

  if(!array_key_exists('role', $user) || !in_array($user['role'], ['admin', 'editor', 'translator'])) {
    header('HTTP/1.0 401 Unauthorized');
    return [];
  }

  $stmt = $db2->prepare('SELECT * from questions WHERE id = ?');
  $stmt->execute([$id]);
  $question = $stmt->fetch();
  $question['live'] = !!$question['live'];

  // fetch translations
  $stmt = $db2->prepare('SELECT * FROM question_translations WHERE question_id = ?');
  $stmt->execute([$id]);
  while($row = $stmt->fetch()) {
    $question['languages'][] = $row['language_id'];

    if($row['language_id'] === 1) {
      $question['question'] = $row['question'];
      $question['answer'] = $row['answer'];
    }
  }

  // fetch all cards
  $stmt = $db2->prepare('
    SELECT c.*
    FROM question_cards as qc
    LEFT JOIN cards as c ON c.id = qc.card_id
    WHERE question_id = ?
    ORDER BY sort, layout, name');
  $stmt->execute([$id]);
  while($row = $stmt->fetch()) {
    $question['cards'][] = [
      'id' => $row['id'],
      'name' => $row['name'],
    ];
  }

  return $question;
}

function getAdminSuggest($db, $name) {
  global $db2;

  $user = auth($db);
  if(!array_key_exists('role', $user) || !in_array($user['role'], ['admin', 'editor', 'translator'])) {
    header('HTTP/1.0 401 Unauthorized');
    return [];
  }

  $stmt = $db2->prepare('SELECT id, name, full_name FROM cards WHERE name LIKE ? ORDER BY name LIMIT 10');
  $stmt->execute([$name . '%']);

  return $stmt->fetchAll();
}

function postAdminSave($db) {
  $user = auth($db);
  $question = json_decode(file_get_contents('php://input'));
  $id = 0;
  if(isset($question->id)) $id = intval($question->id);
  if(isset($user['role']) && (!$id || ($id && in_array($user['role'],array("admin", "editor"))))){
    if(!$id) {
      $query = "SELECT MAX(id)+1 id FROM questions";
      $result = $db->query($query) or die($db->error);
      $id = $result->fetch_assoc()['id'];
      $result->free();
      $question->live = 0;
      $question->minor = 0;
      if(!in_array($user['role'],array("admin", "editor"))) $question->author = $user['name'];
    }
    // question basics
    $parameters = array("id = '".$id."'");
    if(isset($question->live)) $parameters[] = "live = '".intval($question->live)."'";
    if(isset($question->author)) $parameters[] = "author = '".$db->real_escape_string($question->author)."'";
    if(isset($question->difficulty)) $parameters[] = "difficulty = '".intval($question->difficulty)."'";
    $query = join(",",$parameters);
    if(count($parameters)) $db->query("INSERT INTO questions SET $query ON DUPLICATE KEY UPDATE $query") or die($db->error);
    // english text
    if(isset($question->question)) {
      $query = "REPLACE INTO question_translations SET
        question_id = '".$id."', language_id = 1,
        question = '".$db->real_escape_string($question->question)."',
        answer = '".$db->real_escape_string($question->answer)."'";
      if(isset($question->minor) && $question->minor && isset($question->changedate)) {
        $query .= ", changedate = '".$db->real_escape_string($question->changedate)."'";
      }
      $db->query($query) or die($db->error);
    }
    // cards
    if(isset($question->cards)) {
      $db->query("DELETE FROM question_cards WHERE question_id = '".$id."'") or die($db->error);
      $cards = array();
      foreach($question->cards as $index=>$card) {
        if(intval($card->id)) $cards[] = "(".$id.",".intval($card->id).",".intval($index).")";
      }
      $query = "INSERT INTO question_cards (question_id, card_id, sort) VALUES ".join(",",$cards);
      $db->query($query) or die($db->error);
    }
    return "success";
  } else {
    header('HTTP/1.0 401 Unauthorized');
    return "unauthorized";
  }
}

function deleteAdminQuestion($db, $id) {
  $user = auth($db);
  if($_SERVER['REQUEST_METHOD'] == "POST" && isset($user['role']) && in_array($user['role'],array("admin", "editor"))){
    if(intval($id)) {
      $query = "DELETE FROM questions WHERE id = '".intval($id)."' LIMIT 1";
      $db->query($query) or die($db->error);
      return "success";
    } else {
      return "missingid";
    }
  } else {
    header('HTTP/1.0 401 Unauthorized');
    return "unauthorized";
  }
}

function getAdminTranslations($db, $language) {
  $user = auth($db);
  $language = intval($language);
  if(isset($user['role']) && in_array($user['role'],array("admin", "editor", "translator"))
     && (!count($user['languages']) || in_array($language,$user['languages']))) {
    $query = "SELECT qt.question_id, qt2.changedate, q.live, GROUP_CONCAT(IFNULL(ct.name, c.name) ORDER BY sort ASC SEPARATOR '|') cards,
      IF(qt2.question IS NULL OR qt2.answer IS NULL,'untranslated',IF(qt.changedate > qt2.changedate,'outdated','translated')) status
      FROM question_translations qt
      LEFT JOIN question_translations qt2 ON qt2.question_id = qt.question_id AND qt2.language_id = '$language'
      LEFT JOIN questions q ON q.id = qt.question_id
      LEFT JOIN question_cards qc ON qc.question_id = qt.question_id
      LEFT JOIN cards c ON c.id = qc.card_id
      LEFT JOIN card_translations ct ON ct.card_id = qc.card_id AND ct.language_id = '$language'
      WHERE qt.language_id = 1
      GROUP BY qt.question_id
      ORDER BY qt.question_id DESC";
    $result = $db->query($query) or die($db->error);
    $translations = array();
    while($row = $result->fetch_assoc()) {
      $row['question_id'] = intval($row['question_id']);
      $row['live'] = !!$row['live'];
      $row['cards'] = explode("|", $row['cards']);
      foreach($row as $field=>$value) {
        if($value === null) unset($row[$field]);
      }
      $translations[] = $row;
    }
    $result->free();
    return $translations;
  } else {
    header('HTTP/1.0 401 Unauthorized');
    return array();
  }
}

function postAdminTranslate($db) {
  $user = auth($db);
  $translation = json_decode(file_get_contents('php://input'));
  if(isset($user['role']) && in_array($user['role'],array("admin", "editor", "translator"))
       && (!count($user['languages']) || in_array(intval($translation->language_id),$user['languages']))) {
    if(intval($translation->id) && intval($translation->language_id)) {
      if(isset($translation->question) && $translation->question
         && isset($translation->answer) && $translation->answer) {
        // insert new translation
        $query = "REPLACE INTO question_translations SET
          question_id = '".$translation->id."', language_id = '".$translation->language_id."',
          question = '".$db->real_escape_string($translation->question)."',
          answer = '".$db->real_escape_string($translation->answer)."'";
        $db->query($query) or die($db->error);
      } else {
        // delete old translation
        $query = "DELETE FROM question_translations
          WHERE question_id = '".$translation->id."' AND language_id = '".$translation->language_id."' LIMIT 1";
        $db->query($query) or die($db->error);
      }
      return "success";
    } else {
      return "missingid";
    }
  } else {
    header('HTTP/1.0 401 Unauthorized');
    return "unauthorized";
  }
}

function getAdminTranslation($db, $language, $id) {
  $user = auth($db);
  $language = intval($language);
  if(isset($user['role']) && in_array($user['role'],array("admin", "editor", "translator"))
     && (!count($user['languages']) || in_array($language,$user['languages']))) {
    $query = "SELECT q.*, qt.*, qt2.question question_translated, qt2.answer answer_translated,
       qt2.changedate changedate_translated,
       GROUP_CONCAT(IFNULL(ct.name, c.name) ORDER BY sort ASC SEPARATOR '|') cards,
       GROUP_CONCAT(IFNULL(ct.multiverseid, 0) ORDER BY sort ASC SEPARATOR '|') cardids
       FROM questions q
       LEFT JOIN question_cards qc ON qc.question_id = q.id
       LEFT JOIN question_translations qt ON qt.question_id = q.id
       LEFT JOIN question_translations qt2 ON qt2.question_id = q.id AND qt2.language_id = '$language'
       LEFT JOIN cards c ON c.id = qc.card_id
       LEFT JOIN card_translations ct ON ct.card_id = qc.card_id AND ct.language_id = '$language'
       WHERE q.id = '".intval($id)."' AND qt.language_id = 1
       GROUP BY q.id";
    $result = $db->query($query) or die($db->error);
    $question = $result->fetch_assoc();
    if($question) {
      $question['difficulty'] = intval($question['difficulty']);
      $question['language_id'] = intval($language);
      unset($question['question_id']);
      $question['id'] = intval($question['id']);
      $question['live'] = !!$question['live'];
      if(isset($question['cards'])) $question['cards'] = explode("|", $question['cards']);
      if(isset($question['cardids'])) $question['cardids'] = explode("|", $question['cardids']);
    }
    $result->free();
    return $question;
  } else {
    header('HTTP/1.0 401 Unauthorized');
    return array();
  }
}

function getAdminUsers($db) {
  global $db2;

  $user = auth($db);
  if(!array_key_exists('role', $user) || !in_array($user['role'], ['admin'])) {
    header('HTTP/1.0 401 Unauthorized');
    return [];
  }

  $users = [];
  $query = $db2->query('SELECT * FROM users ORDER BY role, name');

  while($row = $query->fetch()) {
    $row['languages'] = $row['languages'] ? array_map('intval', explode(',', $row['languages'])) : [];
    $users[] = $row;
  }

  return $users;
}

function postAdminUser($db) {
  global $db2;
  $user = auth($db);

  if(!array_key_exists('role', $user) || !in_array($user['role'], ['admin'])) {
    header('HTTP/1.0 401 Unauthorized');
    return 'unauthorized';
  }

  $userData = json_decode(file_get_contents('php://input'));

  $stmt = $db2->prepare('REPLACE INTO users SET name = :name, email = :email, role = :role, languages = :languages');
  $stmt->execute([
    'name' => $userData->name,
    'email' => $userData->email,
    'role' => $userData->role,
    'languages' => implode(',', $userData->languages ?: []),
  ]);

  return 'success';
}

function deleteAdminUser($db, $email) {
  $user = auth($db);
  if($_SERVER['REQUEST_METHOD'] == "POST" && isset($user['role']) && $user['role']=="admin" && !empty($email)){
    $query = "DELETE FROM users WHERE email = '".$db->real_escape_string($email)."' LIMIT 1";
    $db->query($query) or die($db->error);
    return "success";
  } else {
    header('HTTP/1.0 401 Unauthorized');
    return "unauthorized";
  }
}

if(isset($_GET['action'])) {
  switch(strtolower($_GET['action'])) {
    case "questions":
      echo json_encode(getQuestions($db));
      break;
    case "sets":
      echo json_encode(getSets($db));
      break;
    case "question":
      if(!isset($_GET['id'])) $_GET['id'] = 0;
      if(!isset($_GET['lang'])) $_GET['lang'] = 0;
      echo json_encode(getQuestion($db, $_GET['id'], $_GET['lang']));
      break;
    case "offline":
      echo json_encode(getQuestionsAndCards($db));
      break;
    case "auth":
      if(!isset($_GET['token'])) $_GET['token'] = "";
      echo json_encode(auth($db, $_GET['token']));
      break;
    case "logout":
      $_SESSION['auth'] = "";
      break;
    case "admin-questions":
      echo json_encode(getAdminQuestions($db, isset($_GET['page']) ? $_GET['page'] : 0));
      break;
    case "admin-question":
      if(!isset($_GET['id'])) $_GET['id'] = 0;
      echo json_encode(getAdminQuestion($db, $_GET['id']));
      break;
    case "admin-suggest":
      if(!isset($_GET['name'])) $_GET['name'] = "";
      echo json_encode(getAdminSuggest($db, $_GET['name']));
      break;
    case "admin-save":
      echo json_encode(postAdminSave($db));
      break;
    case "admin-delete":
      if(!isset($_GET['id'])) $_GET['id'] = 0;
      echo json_encode(deleteAdminQuestion($db, $_GET['id']));
      break;
    case "admin-translations":
      if(!isset($_GET['lang'])) $_GET['lang'] = 0;
      echo json_encode(getAdminTranslations($db, $_GET['lang']));
      break;
    case "admin-translation":
      if(!isset($_GET['id'])) $_GET['id'] = 0;
      if(!isset($_GET['lang'])) $_GET['lang'] = 0;
      echo json_encode(getAdminTranslation($db, $_GET['lang'], $_GET['id']));
      break;
    case "admin-translate":
      echo json_encode(postAdminTranslate($db));
      break;
    case "admin-users":
      echo json_encode(getAdminUsers($db));
      break;
    case "admin-saveuser":
      echo json_encode(postAdminUser($db));
      break;
    case "admin-deleteuser":
      if(!isset($_GET['email'])) $_GET['email'] = "";
      echo json_encode(deleteAdminUser($db, $_GET['email']));
      break;
    case "test-auth":
      if(strpos($_SERVER['HTTP_HOST'], 'localhost') === 0) {
        $_SESSION['auth'] = 'boothadmin@gmail.com';
      }
      break;
  }
}
