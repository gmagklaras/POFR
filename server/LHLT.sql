#LHLT.sql - SQL template to make the lhlt.lhltable, which is a list of all the registered databases of the POFR clients on the server
#POFR - Penguin OS Forensic (or Flight) Recorder - 
#A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System 
#and derivatives.
#Copyright (C) 2021,2022 Georgios Magklaras

#This program is free software; you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 2 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License along
#with this program; if not, write to the Free Software Foundation, Inc.,
#51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
`dbname` varchar(59) NOT NULL,
`ciduser` varchar(32) NOT NULL,
`hostname` varchar(130) NOT NULL,
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
