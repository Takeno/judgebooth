<?php
ini_set('memory_limit', '512M');
ini_set('max_execution_time', '0');
$db = new mysqli('localhost', 'root', 'root', 'judgebooth');
$db->set_charset("utf8");

/*------- card data --------
// Sets
$sets = json_decode(file_get_contents("http://mtgjson.com/json/AllSetsArray.json"));
echo "loaded ".count($sets)." sets\n";
foreach($sets as $set) {
  $query = "name='".$db->real_escape_string($set->name)."',";
  if(isset($set->gathererCode)) {
    $query .= "code='".$db->real_escape_string($set->gathererCode)."',";
  } else {
    $query .= "code='".$db->real_escape_string($set->code)."',";
  }
  $query .= "releasedate='".$db->real_escape_string($set->releaseDate)."'";
  $query = "INSERT INTO sets SET $query ON DUPLICATE KEY UPDATE $query";
  $db->query($query) or die($db->error);
}
#*/

/*
// Card texts, translations and printings
$cards = json_decode(file_get_contents("http://mtgjson.com/json/AllCards-x.json"));
echo "loaded cards\n";

foreach($cards as $card) {
  $query = "name='".$db->real_escape_string($card->name)."',
  layout='".$db->real_escape_string($card->layout)."',
  manacost='".$db->real_escape_string($card->manaCost)."',
  type='".$db->real_escape_string($card->type)."',
  text='".$db->real_escape_string($card->text)."',
  power='".$db->real_escape_string($card->power)."',
  toughness='".$db->real_escape_string($card->toughness)."'";
  if(isset($card->names)) $query .= ", full_name='".$db->real_escape_string(join(" // ",$card->names))."'";
  $query = "INSERT INTO cards SET $query ON DUPLICATE KEY UPDATE $query";
  $db->query($query) or die($db->error);
  $result = $db->query("SELECT id FROM cards WHERE name = '".$db->real_escape_string($card->name)."' LIMIT 1");
  while($row = $result->fetch_assoc()) {
    $card->id = $row['id'];
  }
  $result->free();

  # printings
  foreach($card->printings as $printing) {
    $result = $db->query("SELECT id FROM sets WHERE name = '".$db->real_escape_string($printing)."' LIMIT 1");
    while($row = $result->fetch_assoc()) {
      $db->query("INSERT IGNORE INTO card_sets SET card_id='".$card->id."', set_id='".$row['id']."'") or die($db->error);
    }
    $result->free();
  }
  # translations
  if($card->foreignNames) {
    foreach($card->foreignNames as $translation) {
      $result = $db->query("SELECT id FROM languages WHERE name = '".$db->real_escape_string($translation->language)."' LIMIT 1");
      while($row = $result->fetch_assoc()) {
        $db->query("INSERT IGNORE INTO card_translations SET card_id='".$card->id."', language_id='".$row['id']."', name='".$db->real_escape_string($translation->name)."'");
      }
      $result->free();
    }
  }
}
#*/

/*
// Tokens
$tokens = json_decode(file_get_contents("tokens.json"));
echo "loaded tokens\n";

foreach($tokens as $token) {
  $query = "name='".$db->real_escape_string($token->name)."',
  layout='".$db->real_escape_string($token->layout)."',
  url='".$db->real_escape_string($token->url)."',
  type='".$db->real_escape_string($token->type)."',
  text='".$db->real_escape_string($token->text)."',
  power='".$db->real_escape_string($token->power)."',
  toughness='".$db->real_escape_string($token->toughness)."'";
  $query = "INSERT INTO cards SET $query ON DUPLICATE KEY UPDATE $query";
  $db->query($query) or die($db->error);
}
#*/

#/* Import english question base
$questions = json_decode(file_get_contents("https://spreadsheets.google.com/feeds/cells/0Aig7p68d7NwYdFdhVVNHXzdDQ0Qwd0U3R0FNbkd6Ync/oda/public/values?alt=json"));
echo count($questions->feed->entry)." cells loaded\n";
$questionsArray = array();
foreach($questions->feed->entry as $cell) {
  $cell = $cell->{'gs$cell'};
  if(!isset($questionsArray[$cell->row])) $questionsArray[$cell->row] = array();
  $questionsArray[$cell->row][$cell->col] = $cell->{'$t'};
}
foreach($questionsArray as $row) {
  if($row[1] == "Number") continue;
  $id = $row[1];
  $live = isset($row[2]) && $row[2] ? 1:0;
  $cards = array();
  for($x = 4;$x<9; $x++) {
    if(isset($row[$x]) && $row[$x]) {
      if(strstr($row[$x],"//") > -1) {
        foreach(explode("//",$row[$x]) as $card) {
          array_push($cards, $db->real_escape_string(trim($card)));
        }
      } else {
        array_push($cards, $db->real_escape_string(trim($row[$x])));
      }
    }
  }
  $question = $db->real_escape_string($row[9]);
  $answer = $db->real_escape_string($row[10]);
  if(!isset($row[11])) $row[11] = null;
  $author = $db->real_escape_string($row[11]);
  $difficulty = array_search(strtolower($row[12]),array("easy","medium","hard"));

  $db->query("REPLACE INTO questions SET id='".$id."', live='".$live."', author='".$author."', difficulty='".$difficulty."'") or die($db->error);
  $db->query("REPLACE INTO question_translations SET question_id='".$id."', language_id='1', question='".$question."', answer='".$answer."'") or die($db->error);
  foreach($cards as $card) {
    $card = str_replace(" token", "", $card);
    $result = $db->query("SELECT * FROM cards WHERE name = '".$card."' LIMIT 1");
    $row = $result->fetch_assoc();
    if(isset($row['id'])) {
      $db->query("REPLACE INTO question_cards SET question_id='".$id."', card_id='".$row['id']."'") or die($db->error);
    } else {
      die("can't find card ".$card."\n");
    }
    $result->free();
  }
}
#*/

#/* Import translations
$translations = array(
  "cn" => 'https://spreadsheets.google.com/feeds/cells/0AqlIQacaL79AdDZoM0toVk5YTG9CWndTSldQODVuVlE/oda/public/values?alt=json',
  "tw" => 'https://spreadsheets.google.com/feeds/cells/0AvKY1T4Hb-_GdG1LZFhDNFpmcFNKZmt0LTZHcmllM2c/oda/public/values?alt=json',
  "ru" => 'https://spreadsheets.google.com/feeds/cells/0AqlIQacaL79AdFlCV2dOaTdzYlhsaHF3UVk0b2JlVVE/oda/public/values?alt=json',
  "fr" => 'https://spreadsheets.google.com/feeds/cells/0AqlIQacaL79AdDdEYVNaYWt3LUo0emxWenhMakRvYXc/oda/public/values?alt=json'
);
foreach($translations as $language=>$translation) {
  $count = 0;
  $questions = json_decode(file_get_contents($translation));
  echo count($questions->feed->entry)." cells loaded\n";
  $questionsArray = array();
  foreach($questions->feed->entry as $cell) {
    $cell = $cell->{'gs$cell'};
    if(!isset($questionsArray[$cell->row])) $questionsArray[$cell->row] = array();
    $questionsArray[$cell->row][$cell->col] = $cell->{'$t'};
  }
  foreach($questionsArray as $row) {
    if(isset($row[1]) && $row[1] == "Number") continue;
    if(!isset($row[2]) || !$row[2]) continue; # skip questions not marked as "done"
    $id = $row[1];
    $question = $db->real_escape_string(strip_tags($row[9]));
    $answer = $db->real_escape_string(strip_tags($row[10]));
    $db->query("REPLACE INTO question_translations SET question_id='".$id."', language_id=(SELECT id FROM languages WHERE code='".$language."' LIMIT 1), question='".$question."', answer='".$answer."'") or die($db->error);
    $count++;
  }
  echo "$count questions translated to $language\n";
}

#*/
$db->close();

