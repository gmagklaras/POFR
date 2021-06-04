/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `lhltable`
--

DROP TABLE IF EXISTS `lhltable`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;

CREATE TABLE `lhltable` (
`hostid` bigint NOT NULL AUTO_INCREMENT,
`uuid` varchar(36) NOT NULL,
`cid` varchar(59) NOT NULL,
`ciduser` varchar(32) NOT NULL,
`lastip` varchar(35),
`ryear` smallint NOT NULL,
`rmonth` tinyint(4) NOT NULL,
`rday` tinyint(4) NOT NULL,
`rmin` tinyint(4) NOT NULL,
`rhour` tinyint(4) NOT NULL,
`rsec` tinyint(4) NOT NULL,	
PRIMARY KEY (`hostid`)
) ENGINE=MyISAM DEFAULT CHARACTER SET=ucs2;
/*!40101 SET character_set_client = @saved_cs_client */;
