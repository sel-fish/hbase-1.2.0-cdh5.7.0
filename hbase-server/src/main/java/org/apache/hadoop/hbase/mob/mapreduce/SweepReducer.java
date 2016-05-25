/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.mob.mapreduce;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.PathFilter;
import org.apache.hadoop.hbase.Cell;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.InvalidFamilyOperationException;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.KeyValueUtil;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.HTable;
import org.apache.hadoop.hbase.io.HFileLink;
import org.apache.hadoop.hbase.io.hfile.CacheConfig;
import org.apache.hadoop.hbase.mapreduce.TableInputFormat;
import org.apache.hadoop.hbase.mob.MobConstants;
import org.apache.hadoop.hbase.mob.MobFile;
import org.apache.hadoop.hbase.mob.MobFileName;
import org.apache.hadoop.hbase.mob.MobUtils;
import org.apache.hadoop.hbase.mob.mapreduce.SweepJob.DummyMobAbortable;
import org.apache.hadoop.hbase.mob.mapreduce.SweepJob.SweepCounter;
import org.apache.hadoop.hbase.regionserver.BloomType;
import org.apache.hadoop.hbase.regionserver.DefaultMemStore;
import org.apache.hadoop.hbase.regionserver.StoreFile;
import org.apache.hadoop.hbase.regionserver.StoreFileScanner;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hbase.util.FSUtils;
import org.apache.hadoop.hbase.zookeeper.ZooKeeperWatcher;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.SequenceFile;
import org.apache.hadoop.io.SequenceFile.CompressionType;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.zookeeper.KeeperException;

/**
 * The reducer of a sweep job.
 * This reducer merges the small mob files into bigger ones, and write visited
 * names of mob files to a sequence file which is used by the sweep job to delete
 * the unused mob files.
 * The key of the input is a file name, the value is a collection of KeyValue where
 * the KeyValue is the actual cell (its format is valueLength + fileName) in HBase.
 * In this reducer, we could know how many cells exist in HBase for a mob file.
 * If the existCellSize/mobFileSize < compactionRatio, this mob
 * file needs to be merged.
 */
@InterfaceAudience.Private
public class SweepReducer extends Reducer<Text, KeyValue, Writable, Writable> {

  private static final Log LOG = LogFactory.getLog(SweepReducer.class);

  private SequenceFile.Writer writer = null;
  private MemStoreWrapper memstore;
  private Configuration conf;
  private FileSystem fs;

  private Path familyDir;
  private CacheConfig cacheConfig;
  private long compactionBegin;
  private HTable table;
  private HColumnDescriptor family;
  private long mobCompactionDelay;
  private Path mobTableDir;

  @Override
  protected void setup(Context context) throws IOException, InterruptedException {
    this.conf = context.getConfiguration();
    this.fs = FileSystem.get(conf);
    // the MOB_SWEEP_JOB_DELAY is ONE_DAY by default. Its value is only changed when testing.
    mobCompactionDelay = conf.getLong(SweepJob.MOB_SWEEP_JOB_DELAY, SweepJob.ONE_DAY);
    String tableName = conf.get(TableInputFormat.INPUT_TABLE);
    String familyName = conf.get(TableInputFormat.SCAN_COLUMN_FAMILY);
    TableName tn = TableName.valueOf(tableName);
    this.familyDir = MobUtils.getMobFamilyPath(conf, tn, familyName);
    HBaseAdmin admin = new HBaseAdmin(this.conf);
    try {
      family = admin.getTableDescriptor(tn).getFamily(Bytes.toBytes(familyName));
      if (family == null) {
        // this column family might be removed, directly return.
        throw new InvalidFamilyOperationException("Column family '" + familyName
            + "' does not exist. It might be removed.");
      }
    } finally {
      try {
        admin.close();
      } catch (IOException e) {
        LOG.warn("Fail to close the HBaseAdmin", e);
      }
    }
    // disable the block cache.
    Configuration copyOfConf = new Configuration(conf);
    copyOfConf.setFloat(HConstants.HFILE_BLOCK_CACHE_SIZE_KEY, 0f);
    this.cacheConfig = new CacheConfig(copyOfConf);

    table = new HTable(this.conf, Bytes.toBytes(tableName));
    table.setAutoFlush(false, false);

    table.setWriteBufferSize(1 * 1024 * 1024); // 1MB
    memstore = new MemStoreWrapper(context, fs, table, family, new DefaultMemStore(), cacheConfig);

    // The start time of the sweep tool.
    // Only the mob files whose creation time is older than startTime-oneDay will be handled by the
    // reducer since it brings inconsistency to handle the latest mob files.
    this.compactionBegin = conf.getLong(MobConstants.MOB_SWEEP_TOOL_COMPACTION_START_DATE, 0);
    mobTableDir = FSUtils.getTableDir(MobUtils.getMobHome(conf), tn);
  }

  private SweepPartition createPartition(SweepPartitionId id, Context context) throws IOException {
    return new SweepPartition(id, context);
  }

  @Override
  public void run(Context context) throws IOException, InterruptedException {
    String jobId = context.getConfiguration().get(SweepJob.SWEEP_JOB_ID);
    String owner = context.getConfiguration().get(SweepJob.SWEEP_JOB_SERVERNAME);
    String sweeperNode = context.getConfiguration().get(SweepJob.SWEEP_JOB_TABLE_NODE);
    ZooKeeperWatcher zkw = new ZooKeeperWatcher(context.getConfiguration(), jobId,
        new DummyMobAbortable());
    FSDataOutputStream fout = null;
    try {
      SweepJobNodeTracker tracker = new SweepJobNodeTracker(zkw, sweeperNode, owner);
      tracker.start();
      setup(context);
      // create a sequence contains all the visited file names in this reducer.
      String dir = this.conf.get(SweepJob.WORKING_VISITED_DIR_KEY);
      Path nameFilePath = new Path(dir, UUID.randomUUID().toString()
          .replace("-", MobConstants.EMPTY_STRING));
      fout = fs.create(nameFilePath, true);
      writer = SequenceFile.createWriter(context.getConfiguration(), fout, String.class,
          String.class, CompressionType.NONE, null);
      SweepPartitionId id;
      SweepPartition partition = null;
      // the mob files which have the same start key and date are in the same partition.
      while (context.nextKey()) {
        Text key = context.getCurrentKey();
        String keyString = key.toString();
        id = SweepPartitionId.create(keyString);
        if (null == partition || !id.equals(partition.getId())) {
          // It's the first mob file in the current partition.
          if (null != partition) {
            // this mob file is in different partitions with the previous mob file.
            // directly close.
            partition.close();
          }
          // create a new one
          partition = createPartition(id, context);
        }
        if (partition != null) {
          // run the partition
          partition.execute(key, context.getValues());
        }
      }
      if (null != partition) {
        partition.close();
      }
      writer.hflush();
    } catch (KeeperException e) {
      throw new IOException(e);
    } finally {
      cleanup(context);
      zkw.close();
      if (writer != null) {
        IOUtils.closeStream(writer);
      }
      if (fout != null) {
        IOUtils.closeStream(fout);
      }
      if (table != null) {
        try {
          table.close();
        } catch (IOException e) {
          LOG.warn(e);
        }
      }
    }

  }

  /**
   * The mob files which have the same start key and date are in the same partition.
   * The files in the same partition are merged together into bigger ones.
   */
  public class SweepPartition {

    private final SweepPartitionId id;
    private final Context context;
    private boolean memstoreUpdated = false;
    private boolean mergeSmall = false;
    private final Map<String, MobFileStatus> fileStatusMap = new HashMap<String, MobFileStatus>();
    private final List<Path> toBeDeleted = new ArrayList<Path>();

    public SweepPartition(SweepPartitionId id, Context context) throws IOException {
      this.id = id;
      this.context = context;
      memstore.setPartitionId(id);
      init();
    }

    public SweepPartitionId getId() {
      return this.id;
    }

    /**
     * Prepares the map of files.
     *
     * @throws IOException
     */
    private void init() throws IOException {
      FileStatus[] fileStats = listStatus(familyDir, id.getStartKey());
      if (null == fileStats) {
        return;
      }

      int smallFileCount = 0;
      float compactionRatio = conf.getFloat(MobConstants.MOB_SWEEP_TOOL_COMPACTION_RATIO,
          MobConstants.DEFAULT_SWEEP_TOOL_MOB_COMPACTION_RATIO);
      long compactionMergeableSize = conf.getLong(
          MobConstants.MOB_SWEEP_TOOL_COMPACTION_MERGEABLE_SIZE,
          MobConstants.DEFAULT_SWEEP_TOOL_MOB_COMPACTION_MERGEABLE_SIZE);
      // list the files. Just merge the hfiles, don't merge the hfile links.
      // prepare the map of mob files. The key is the file name, the value is the file status.
      for (FileStatus fileStat : fileStats) {
        MobFileStatus mobFileStatus = null;
        if (!HFileLink.isHFileLink(fileStat.getPath())) {
          mobFileStatus = new MobFileStatus(fileStat, compactionRatio, compactionMergeableSize);
          if (mobFileStatus.needMerge()) {
            smallFileCount++;
          }
          // key is file name (not hfile name), value is hfile status.
          fileStatusMap.put(fileStat.getPath().getName(), mobFileStatus);
        }
      }
      if (smallFileCount >= 2) {
        // merge the files only when there're more than 1 files in the same partition.
        this.mergeSmall = true;
      }
    }

    /**
     * Flushes the data into mob files and store files, and archives the small
     * files after they're merged.
     * @throws IOException
     */
    public void close() throws IOException {
      if (null == id) {
        return;
      }
      // flush remain key values into mob files
      if (memstoreUpdated) {
        memstore.flushMemStore();
      }
      List<StoreFile> storeFiles = new ArrayList<StoreFile>(toBeDeleted.size());
      // delete samll files after compaction
      for (Path path : toBeDeleted) {
        LOG.info("[In Partition close] Delete the file " + path + " in partition close");
        storeFiles.add(new StoreFile(fs, path, conf, cacheConfig, BloomType.NONE));
      }
      if (!storeFiles.isEmpty()) {
        try {
          MobUtils.removeMobFiles(conf, fs, table.getName(), mobTableDir, family.getName(),
              storeFiles);
          context.getCounter(SweepCounter.FILE_TO_BE_MERGE_OR_CLEAN).increment(storeFiles.size());
        } catch (IOException e) {
          LOG.error("Fail to archive the store files " + storeFiles, e);
        }
        storeFiles.clear();
      }
      fileStatusMap.clear();
    }

    /**
     * Merges the small mob files into bigger ones.
     * @param fileName The current mob file name.
     * @param values The collection of KeyValues in this mob file.
     * @throws IOException
     */
    public void execute(Text fileName, Iterable<KeyValue> values) throws IOException {
      if (null == values) {
        return;
      }
      MobFileName mobFileName = MobFileName.create(fileName.toString());
      LOG.info("[In reducer] The file name: " + fileName.toString());
      MobFileStatus mobFileStat = fileStatusMap.get(mobFileName.getFileName());
      if (null == mobFileStat) {
        LOG.info("[In reducer] Cannot find the file, probably this record is obsolete");
        return;
      }
      // only handle the files that are older then one day.
      if (compactionBegin - mobFileStat.getFileStatus().getModificationTime()
          <= mobCompactionDelay) {
        return;
      }
      // write the hfile name
      writer.append(mobFileName.getFileName(), MobConstants.EMPTY_STRING);
      Set<KeyValue> kvs = new HashSet<KeyValue>();
      for (KeyValue kv : values) {
        if (kv.getValueLength() > Bytes.SIZEOF_INT) {
          mobFileStat.addValidSize(Bytes.toInt(kv.getValueArray(), kv.getValueOffset(),
              Bytes.SIZEOF_INT));
        }
        kvs.add(kv.createKeyOnly(false));
      }
      // If the mob file is a invalid one or a small one, merge it into new/bigger ones.
      if (mobFileStat.needClean() || (mergeSmall && mobFileStat.needMerge())) {
        context.getCounter(SweepCounter.INPUT_FILE_COUNT).increment(1);
        MobFile file = MobFile.create(fs,
            new Path(familyDir, mobFileName.getFileName()), conf, cacheConfig);
        StoreFileScanner scanner = null;
        file.open();
        try {
          scanner = file.getScanner();
          scanner.seek(KeyValueUtil.createFirstOnRow(HConstants.EMPTY_BYTE_ARRAY));
          Cell cell;
          while (null != (cell = scanner.next())) {
            KeyValue kv = KeyValueUtil.ensureKeyValue(cell);
            KeyValue keyOnly = kv.createKeyOnly(false);
            if (kvs.contains(keyOnly)) {
              // write the KeyValue existing in HBase to the memstore.
              memstore.addToMemstore(kv);
              memstoreUpdated = true;
            }
          }
        } finally {
          if (scanner != null) {
            scanner.close();
          }
          file.close();
        }
        toBeDeleted.add(mobFileStat.getFileStatus().getPath());
      }
    }

    /**
     * Lists the files with the same prefix.
     * @param p The file path.
     * @param prefix The prefix.
     * @return The files with the same prefix.
     * @throws IOException
     */
    private FileStatus[] listStatus(Path p, String prefix) throws IOException {
      return fs.listStatus(p, new PathPrefixFilter(prefix));
    }
  }

  static class PathPrefixFilter implements PathFilter {

    private final String prefix;

    public PathPrefixFilter(String prefix) {
      this.prefix = prefix;
    }

    public boolean accept(Path path) {
      return path.getName().startsWith(prefix, 0);
    }

  }

  /**
   * The sweep partition id.
   * It consists of the start key and date.
   * The start key is a hex string of the checksum of a region start key.
   * The date is the latest timestamp of cells in a mob file.
   */
  public static class SweepPartitionId {
    private String date;
    private String startKey;

    public SweepPartitionId(MobFileName fileName) {
      this.date = fileName.getDate();
      this.startKey = fileName.getStartKey();
    }

    public SweepPartitionId(String date, String startKey) {
      this.date = date;
      this.startKey = startKey;
    }

    public static SweepPartitionId create(String key) {
      return new SweepPartitionId(MobFileName.create(key));
    }

    @Override
    public boolean equals(Object anObject) {
      if (this == anObject) {
        return true;
      }
      if (anObject instanceof SweepPartitionId) {
        SweepPartitionId another = (SweepPartitionId) anObject;
        if (this.date.equals(another.getDate()) && this.startKey.equals(another.getStartKey())) {
          return true;
        }
      }
      return false;
    }

    public String getDate() {
      return this.date;
    }

    public String getStartKey() {
      return this.startKey;
    }

    public void setDate(String date) {
      this.date = date;
    }

    public void setStartKey(String startKey) {
      this.startKey = startKey;
    }
  }

  /**
   * The mob file status used in the sweep reduecer.
   */
  private static class MobFileStatus {
    private FileStatus fileStatus;
    private int validSize;
    private long size;

    private float compactionRatio = MobConstants.DEFAULT_SWEEP_TOOL_MOB_COMPACTION_RATIO;
    private long compactionMergeableSize =
        MobConstants.DEFAULT_SWEEP_TOOL_MOB_COMPACTION_MERGEABLE_SIZE;

    /**
     * @param fileStatus The current FileStatus.
     * @param compactionRatio compactionRatio the invalid ratio.
     * If there're too many cells deleted in a mob file, it's regarded as invalid,
     * and needs to be written to a new one.
     * If existingCellSize/fileSize < compactionRatio, it's regarded as a invalid one.
     * @param compactionMergeableSize compactionMergeableSize If the size of a mob file is less
     * than this value, it's regarded as a small file and needs to be merged
     */
    public MobFileStatus(FileStatus fileStatus, float compactionRatio,
        long compactionMergeableSize) {
      this.fileStatus = fileStatus;
      this.size = fileStatus.getLen();
      validSize = 0;
      this.compactionRatio = compactionRatio;
      this.compactionMergeableSize = compactionMergeableSize;
    }

    /**
     * Add size to this file.
     * @param size The size to be added.
     */
    public void addValidSize(int size) {
      this.validSize += size;
    }

    /**
     * Whether the mob files need to be cleaned.
     * If there're too many cells deleted in this mob file, it needs to be cleaned.
     * @return True if it needs to be cleaned.
     */
    public boolean needClean() {
      return validSize < compactionRatio * size;
    }

    /**
     * Whether the mob files need to be merged.
     * If this mob file is too small, it needs to be merged.
     * @return True if it needs to be merged.
     */
    public boolean needMerge() {
      return this.size < compactionMergeableSize;
    }

    /**
     * Gets the file status.
     * @return The file status.
     */
    public FileStatus getFileStatus() {
      return fileStatus;
    }
  }
}
